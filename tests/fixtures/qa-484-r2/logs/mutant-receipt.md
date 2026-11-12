# QA-484 round-2 mutant receipt

| item | mutant | control | mutant actual | expected mutant | killed |
| --- | --- | --- | --- | --- | --- |
| M2 | watch_review_decision | current | review_due | review_due | yes |
| M3 | watch_structural_failures | ['profile schema_version must be 1.0'] | ['one or more watched source packs are due or blocked', 'profile schema_version must be 1.0'] | ['one or more watched source packs are due or blocked', 'profile schema_version must be 1.0'] | yes |
| M0 | watch_build_pack_unfiltered | True | False | False | yes |
| E1 | evaluator_cli_access | kill_session_and_escalate_board | monitor_no_incident | monitor_no_incident | yes |
| E2 | evaluator_cli_tamper | kill_session_and_escalate_board | monitor_no_incident | monitor_no_incident | yes |
| E3 | evaluator_cli_resume | hold_for_forensics | monitor_no_incident | monitor_no_incident | yes |
| E4 | evaluator_json_false_access | monitor_no_incident | kill_session_and_escalate_board | kill_session_and_escalate_board | yes |
| E4b | evaluator_json_false_tamper | monitor_no_incident | kill_session_and_escalate_board | kill_session_and_escalate_board | yes |
| E4c | evaluator_json_false_resume | monitor_no_incident | hold_for_forensics | hold_for_forensics | yes |
| E5 | evaluator_cli_access | kill_session_and_escalate_board | contain_and_open_war_room | contain_and_open_war_room | yes |
| E5b | evaluator_cli_tamper | kill_session_and_escalate_board | contain_and_open_war_room | contain_and_open_war_room | yes |
| E5c | evaluator_cli_resume | hold_for_forensics | contain_and_open_war_room | contain_and_open_war_room | yes |
| E5d | evaluator_missing_access | contain_and_open_war_room | monitor_no_incident | monitor_no_incident | yes |
| E5e | evaluator_missing_tamper | contain_and_open_war_room | monitor_no_incident | monitor_no_incident | yes |
| E5f | evaluator_missing_resume | contain_and_open_war_room | monitor_no_incident | monitor_no_incident | yes |
| G1 | ir_assigned_class | True | False | False | yes |
| G2 | ir_containment | [True, True] | [False, False] | [False, False] | yes |
| G3 | ir_tabletop | True | False | False | yes |
| A1 | mcp06_aliases | ['Prompt Injection via Contextual Payloads'] | None | None | yes |

M1 is the overdue fixture at `tests/fixtures/source-freshness/`; killed by `test_written_pack_omits_editorial_due_failures`.
M2b (`validate_coverage` due_count flipped) is equivalent and is not killed separately.
