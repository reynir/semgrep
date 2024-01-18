open Common
module OutT = Semgrep_output_v1_t
module Sarif_v = Sarif.Sarif_v_2_1_0_v

let sarif_severity_of_severity = function
  | `Info -> `Note
  | `Warning -> `Warning
  | `Error -> `Error
  | `Experiment
  | `Inventory ->
      raise Todo

let tags_of_metadata metadata =
  (* XXX: Tags likely have to be strings, but what do we do with non-string json?! *)
  let best_effort_string = function
    | JSON.String s -> s
    | non_string -> JSON.string_of_json non_string
  in
  let cwe =
    match JSON.member "cwe" metadata with
    | Some (JSON.Array cwe) -> List_.map best_effort_string cwe
    | Some single_cwe -> [ best_effort_string single_cwe ]
    | None -> []
  in
  let owasp =
    match JSON.member "owasp" metadata with
    | Some (JSON.Array owasp) ->
        List_.map (fun o -> "OWASP-" ^ best_effort_string o) owasp
    | Some o -> [ "OWASP-" ^ best_effort_string o ]
    | None -> []
  in
  let confidence =
    match JSON.member "confidence" metadata with
    | Some c -> [ best_effort_string c ^ " CONFIDENCE" ]
    | None -> []
  in
  let semgrep_policy_slug =
    match JSON.member "semgrep.policy" metadata with
    | Some (JSON.Object _ as sp) -> (
        match JSON.member "slug" sp with
        | Some slug -> [ best_effort_string slug ]
        | None -> [])
    | Some _
    | None ->
        []
  in
  let tags =
    match JSON.member "tags" metadata with
    | Some (JSON.Array tags) -> List_.map best_effort_string tags
    | Some _
    | None ->
        []
  in
  cwe @ owasp @ confidence @ semgrep_policy_slug @ tags

(* We want to produce a json object? with the following shape:
   { id; name;
     shortDescription; fullDescription;
     helpUri; help;
     defaultConfiguration = { level };
     properties }
*)
let rules hide_nudge (hrules : Rule.hrules) =
  let rules = Hashtbl.to_seq hrules in
  let rules =
    Seq.map
      (fun (rule_id, rule) ->
        let metadata = Option.value ~default:JSON.Null rule.Rule.metadata in
        let short_description =
          match JSON.member "shortDescription" metadata with
          | Some (JSON.String shortDescription) -> shortDescription
          | Some _ -> raise Impossible
          | None -> spf "Semgrep Finding: %s" (Rule_ID.to_string rule_id)
        and source, rule_url =
          match JSON.member "source" metadata with
          | Some (JSON.String source) -> (Some source, Some source)
          | Some _
          | None ->
              (None, None)
        and rule_help_text =
          match JSON.member "help" metadata with
          | Some (JSON.String txt) -> txt
          | Some _
          | None ->
              rule.message
        in
        let security_severity =
          (* TODO: no test case for this *)
          match JSON.member "security-severity" metadata with
          | Some json ->
              (* FIXME [ ("security-severity", JSON.to_yojson json) ] *)
              ignore json;
              []
          | None -> []
        in
        let properties =
          let tags = tags_of_metadata metadata in
          [
            ("precision", (*`String*) "very-high");
            ( "tags",
              (*FIXME: `List (List_.map (fun s -> `String s) tags));*)
              String.concat "," tags );
          ]
          @ security_severity
        in
        let nudge_base =
          "💎 Enable cross-file analysis and Pro rules for free at"
        and nudge_url = "sg.run/pro" in
        let nudge_plaintext = spf "\n%s %s" nudge_base nudge_url
        and nudge_md =
          spf "\n\n#### %s <a href='https://%s'>%s</a>" nudge_base nudge_url
            nudge_url
        in
        let text_suffix = if hide_nudge then "" else nudge_plaintext in
        let markdown_interstitial = if hide_nudge then "" else nudge_md in
        let references =
          Option.to_list
            (Option.map (fun s -> spf "[Semgrep Rule](%s)" s) source)
        in
        let other_references =
          match JSON.member "references" metadata with
          | Some (JSON.String s) -> [ spf "[%s](%s)" s s ]
          | Some (JSON.Array xs) ->
              List_.map
                (function
                  | JSON.String s -> spf "[%s](%s)" s s
                  | non_string -> JSON.string_of_json non_string)
                xs
          | Some _
          | None ->
              []
        in
        let references_joined =
          List_.map (fun s -> spf " - %s\n" s) (references @ other_references)
        in
        let references_markdown =
          match references_joined with
          | [] -> ""
          | xs -> "\n\n<b>References:</b>\n" ^ String.concat "" xs
        in
        let default_configuration =
          Sarif_v.create_reporting_configuration
            ~level:(sarif_severity_of_severity rule.severity)
            ()
        in
        let help =
          Sarif_v.create_multiformat_message_string
            ~text:(rule_help_text ^ text_suffix)
            ~markdown:
              (rule_help_text ^ markdown_interstitial ^ references_markdown)
            ()
        in
        let short_description =
          Sarif_v.create_multiformat_message_string ~text:short_description ()
        in
        let full_description =
          Sarif_v.create_multiformat_message_string ~text:rule.message ()
        in
        Sarif_v.create_reporting_descriptor
          ~name:(Rule_ID.to_string rule_id)
          ~id:(Rule_ID.to_string rule_id)
          ~short_description ~full_description ~default_configuration ~help
          ~properties ?help_uri:rule_url ())
      rules
  in
  List.of_seq rules

let fixed_lines (cli_match : OutT.cli_match) fix =
  let lines = String.split_on_char '\n' cli_match.extra.lines in
  match (lines, List.rev lines) with
  | line :: _, last_line :: _ ->
      let first_line_part = Str.first_chars line (cli_match.start.col - 1)
      and last_line_part =
        Str.string_after last_line (cli_match.end_.col - 1)
      in
      String.split_on_char '\n' (first_line_part ^ fix ^ last_line_part)
  | [], _
  | _, [] ->
      []

let sarif_fix (cli_match : OutT.cli_match) =
  match cli_match.extra.fix with
  | None -> None
  | Some fix ->
      let fixed_lines = fixed_lines cli_match fix in
      let description_text =
        spf "%s\n Autofix: Semgrep rule suggested fix" cli_match.extra.message
      in
      let artifact_change =
        let artifact_location =
          Sarif_v.create_artifact_location
            ~uri:(Fpath.to_string cli_match.path)
            ()
        in
        let replacement =
          let region =
            Sarif_v.create_region
              ~start_line:(Int64.of_int cli_match.start.line)
              ~start_column:(Int64.of_int cli_match.start.col)
              ~end_line:(Int64.of_int cli_match.end_.line)
              ~end_column:(Int64.of_int cli_match.end_.col)
              ()
          in
          Sarif_v.create_replacement ~deleted_region:region
            ~inserted_content:
              (Sarif_v.create_artifact_content
                 ~text:(String.concat "\n" fixed_lines)
                 ())
            ()
        in
        Sarif_v.create_artifact_change ~artifact_location
          ~replacements:[ replacement ] ()
      in
      Some
        [
          Sarif_v.create_fix
            ~description:(Sarif_v.create_message ~text:description_text ())
            ~artifact_changes:[ artifact_change ] ();
        ]

let sarif_location (cli_match : OutT.cli_match) message
    (location : OutT.location) content nesting_level =
  `Assoc
    [
      ( "location",
        `Assoc
          [
            ("message", `Assoc [ ("text", `String message) ]);
            ( "physicalLocation",
              `Assoc
                [
                  ( "artifactLocation",
                    `Assoc [ ("uri", `String (Fpath.to_string cli_match.path)) ]
                  );
                  ( "region",
                    `Assoc
                      [
                        ("startLine", `Int location.start.line);
                        ("startColumn", `Int location.start.col);
                        ("endLine", `Int location.end_.line);
                        ("endColumn", `Int location.end_.col);
                        ("snippet", `Assoc [ ("text", `String content) ]);
                        ("message", `Assoc [ ("text", `String message) ]);
                      ] );
                ] );
          ] );
      ("nestingLevel", `Int nesting_level);
    ]

let intermediate_var_locations (cli_match : OutT.cli_match) intermediate_vars =
  intermediate_vars
  |> List_.map (fun ({ location; content } : OutT.match_intermediate_var) ->
         let propagation_message =
           let text =
             spf "Propagator : '%s' @ '%s:%d'" content
               (Fpath.to_string location.path)
               location.start.line
           in
           Sarif_v.create_message ~text ()
         in
         let location =
           let physical_location =
             let region =
               Sarif_v.create_region
                 ~start_line:(Int64.of_int location.start.line)
                 ~start_column:(Int64.of_int location.start.col)
                 ~end_line:(Int64.of_int location.end_.line)
                 ~end_column:(Int64.of_int location.end_.col)
                 ~message:propagation_message
                 ~snippet:(Sarif_v.create_artifact_content ~text:content ())
                 ()
             in
             Sarif_v.create_physical_location ~region
               ~artifact_location:
                 (Sarif_v.create_artifact_location
                    ~uri:(Fpath.to_string cli_match.path)
                    ())
               ()
           in
           Sarif_v.create_location ~message:propagation_message
             ~physical_location ()
         in
         Sarif_v.create_thread_flow_location ~location ~nesting_level:0L ())

let thread_flows (cli_match : OutT.cli_match)
    (dataflow_trace : OutT.match_dataflow_trace) (location : OutT.location)
    content message =
  (* TODO from sarif.py: deal with taint sink *)
  let intermediate_vars = dataflow_trace.intermediate_vars in
  ignore cli_match;
  ignore dataflow_trace;
  let thread_flow_location =
    let source_message =
      let text =
        spf "Source: '%s' @ '%s:%d'" content
          (Fpath.to_string location.path)
          location.start.line
      in
      Sarif_v.create_message ~text ()
    in
    let physical_location =
      let region =
        Sarif_v.create_region
          ~start_line:(Int64.of_int location.start.line)
          ~start_column:(Int64.of_int location.start.col)
          ~end_line:(Int64.of_int location.end_.line)
          ~end_column:(Int64.of_int location.end_.col)
          ~message:source_message
          ~snippet:(Sarif_v.create_artifact_content ~text:content ())
          ()
      in
      Sarif_v.create_physical_location
        ~artifact_location:
          (Sarif_v.create_artifact_location
             ~uri:(Fpath.to_string cli_match.path)
             ())
        ~region ()
    in
    let location =
      Sarif_v.create_location ~message:source_message ~physical_location ()
    in
    Sarif_v.create_thread_flow_location ~location ~nesting_level:0L ()
  in
  let intermediate_var_locations =
    match intermediate_vars with
    | None -> []
    | Some intermediate_vars ->
        intermediate_var_locations cli_match intermediate_vars
  in
  let sink_flow_location =
    let sink_message =
      let text =
        spf "Sink: '%s' @ '%s:%d'"
          (String.trim cli_match.extra.lines) (* rule_match.get_lines() ?! *)
          (Fpath.to_string cli_match.path)
          cli_match.start.line
      in
      Sarif_v.create_message ~text ()
    in
    let location =
      let physical_location =
        let region =
          Sarif_v.create_region
            ~start_line:(Int64.of_int cli_match.start.line)
            ~start_column:(Int64.of_int cli_match.start.col)
            ~end_line:(Int64.of_int cli_match.end_.line)
            ~end_column:(Int64.of_int cli_match.end_.col)
            ~message:sink_message
            ~snippet:
              (Sarif_v.create_artifact_content ~text:cli_match.extra.lines ())
            ()
        in
        Sarif_v.create_physical_location
          ~artifact_location:
            (Sarif_v.create_artifact_location
               ~uri:(Fpath.to_string cli_match.path)
               ())
          ~region ()
      in
      Sarif_v.create_location ~physical_location ~message:sink_message ()
    in
    Sarif_v.create_thread_flow_location ~location ~nesting_level:1L ()
  in
  [
    Sarif_v.create_thread_flow ~message
      ~locations:
        (thread_flow_location
        :: (intermediate_var_locations @ [ sink_flow_location ]))
      ();
  ]

let sarif_codeflow (cli_match : OutT.cli_match) =
  match cli_match.extra.dataflow_trace with
  | None
  | Some { OutT.taint_source = None; _ } ->
      None
  | Some { OutT.taint_source = Some (CliCall _); _ } ->
      Logs.err (fun m ->
          m
            "Emitting SARIF output for unsupported dataflow trace (source is a \
             call)");
      None
  | Some
      ({ taint_source = Some (CliLoc (location, content)); _ } as dataflow_trace)
    ->
      (* TODO from sarif.py: handle taint_sink *)
      let code_flow_message =
        spf "Untrusted dataflow from %s:%d to %s:%d"
          (Fpath.to_string location.path)
          location.start.line
          (Fpath.to_string cli_match.path)
          cli_match.start.line
      in
      let thread_flows =
        let message = Sarif_v.create_message ~text:code_flow_message () in
        thread_flows cli_match dataflow_trace location content message
      in
      Some [ Sarif_v.create_code_flow ~thread_flows () ]

let results (cli_output : OutT.cli_output) =
  let result (cli_match : OutT.cli_match) =
    let location =
      let physical_location =
        let artifact_location =
          Sarif_v.create_artifact_location
            ~uri:(Fpath.to_string cli_match.path)
            ~uri_base_id:"%SRCROOT%" ()
        in
        let region =
          Sarif_v.create_region
            ~snippet:
              (Sarif_v.create_artifact_content ~text:cli_match.extra.lines ())
            ~start_line:(Int64.of_int cli_match.start.line)
            ~start_column:(Int64.of_int cli_match.start.col)
            ~end_line:(Int64.of_int cli_match.end_.line)
            ~end_column:(Int64.of_int cli_match.end_.col)
            ()
        in
        Sarif_v.create_physical_location ~artifact_location ~region ()
      in
      Sarif_v.create_location ~physical_location ()
    in
    let suppressions =
      match cli_match.extra.is_ignored with
      | None
      | Some false ->
          None
      | Some true -> Some [ Sarif_v.create_suppression ~kind:`InSource () ]
    in
    let fix = sarif_fix cli_match in
    let code_flows = sarif_codeflow cli_match in
    let message = Sarif_v.create_message ~text:cli_match.extra.message () in
    Sarif_v.create_result
      ~rule_id:(Rule_ID.to_string cli_match.check_id)
      ~message ~locations:[ location ] ?suppressions
      ~fingerprints:[ ("matchBasedId/v1", cli_match.extra.fingerprint) ]
      ~properties:[] ?fixes:fix ?code_flows ()
  in
  List_.map result cli_output.results

let error_to_sarif_notification (e : OutT.cli_error) =
  let level = sarif_severity_of_severity e.level in
  let message =
    Option.value
      ~default:
        (Option.value
           ~default:(Option.value ~default:"" e.short_msg)
           e.long_msg)
      e.message
  in
  let message = Sarif_v.create_message ~text:message () in
  let descriptor =
    let id = Error.string_of_error_type e.type_ in
    Sarif_v.create_reporting_descriptor_reference ~id ()
  in
  Sarif_v.create_notification ~descriptor ~message ~level ()

let sarif_output hrules (cli_output : OutT.cli_output) =
  let sarif_schema =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
  in
  let engine_label =
    match cli_output.OutT.engine_requested with
    | Some `OSS
    | None ->
        "OSS"
    | Some `PRO -> "PRO"
  in
  let run =
    let hide_nudge =
      (* TODO is_logged_in or is_pro or not is_using_registry *)
      true
    in
    let rules = rules hide_nudge hrules in
    let tool =
      let driver =
        Sarif_v.create_tool_component ~semantic_version:Version.version ~rules
          ~name:(spf "Semgrep %s" engine_label)
          ()
      in
      Sarif_v.create_tool ~driver ()
    in
    let results = results cli_output in
    let invocation =
      (* TODO no test case(s) for executionNotifications being non-empty *)
      let exec_notifs =
        List_.map error_to_sarif_notification cli_output.errors
      in
      Sarif_v.create_invocation ~execution_successful:true
        ~tool_execution_notifications:exec_notifs ()
    in
    Sarif_v.create_run ~tool ~results ~invocations:[ invocation ] ()
  in
  Sarif_v.create_sarif_json_schema ~version:`TwoDotOneDotZero
    ~schema:sarif_schema ~runs:[ run ] ()
