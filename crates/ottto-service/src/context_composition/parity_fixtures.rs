//! Synthetic fixtures carried forward from the original parity experiment.
use super::*;

pub(super) struct Case {
    pub name: &'static str,
    pub claude: bool,
    pub exclude: bool,
    pub repetitions: usize,
    pub bytes: Vec<u8>,
}

pub(super) fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    cases.push(Case { name: "claude-adversarial", claude: true, exclude: false, repetitions: 1, bytes: r########"{"type":"user","timestamp":"2026-10-05T09:00:00Z","sessionId":"first","message":{"content":[{"type":"tool_result","tool_use_id":"later","content":[{"type":"text","text":"α😀\\\nquote\""},{"type":"image","source":{"data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"}}]}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Bash","input":{}}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Read","input":{"file_path":"/synthetic/workspace/docs/guide.md"}}]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z","attachment":{"filename":"MEMORY.md","content":"remember","addedBlocks":["",{"n":1.25,"b":true,"k":["é",null]}]}}
4
{"type":"user","timestamp":"2026-10-05T09:00:00Z","message":{"content":[{"type":"image"},{"type":"tool_result","content":[true,3,"",{"type":"unknown","x":"héllo"}]}]}}
{"type":"summary","timestamp":"2026-10-05T09:00:00Z","isCompactSummary":true}
{"type":"system","timestamp":"2026-10-05T09:00:00Z","subtype":"compact_boundary"}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"content":[]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z"}
{"type":"attachment","timestamp":"bad","ts":"2026-10-04T22:00:00Z","attachment":null}
{"type":"attachment","ts":"2026-10-04T22:00:00Z","sessionId":"final","attachment":{"filename":"notes.html","snippet":"html"}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"z","content":[]}}
{malformed trailing"########.as_bytes().to_vec() });
    cases.push(Case { name: "claude-subagent-include", claude: true, exclude: false, repetitions: 1, bytes: r########"{"type":"user","timestamp":"2026-10-05T09:00:00Z","sessionId":"first","message":{"content":[{"type":"tool_result","tool_use_id":"later","content":[{"type":"text","text":"α😀\\\nquote\""},{"type":"image","source":{"data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"}}]}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Bash","input":{}}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Read","input":{"file_path":"/synthetic/workspace/docs/guide.md"}}]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z","attachment":{"filename":"MEMORY.md","content":"remember","addedBlocks":["",{"n":1.25,"b":true,"k":["é",null]}]}}
4
{"type":"user","timestamp":"2026-10-05T09:00:00Z","message":{"content":[{"type":"image"},{"type":"tool_result","content":[true,3,"",{"type":"unknown","x":"héllo"}]}]}}
{"type":"summary","timestamp":"2026-10-05T09:00:00Z","isCompactSummary":true}
{"type":"system","timestamp":"2026-10-05T09:00:00Z","subtype":"compact_boundary"}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"content":[]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z"}
{"type":"attachment","timestamp":"bad","ts":"2026-10-04T22:00:00Z","attachment":null}
{"type":"attachment","ts":"2026-10-04T22:00:00Z","sessionId":"final","attachment":{"filename":"notes.html","snippet":"html"}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"z","content":[]}}
{"type":"system","timestamp":"2026-10-05T09:00:00Z","isSidechain":true,"agentId":"worker"}"########.as_bytes().to_vec() });
    cases.push(Case { name: "claude-subagent-exclude", claude: true, exclude: true, repetitions: 1, bytes: r########"{"type":"user","timestamp":"2026-10-05T09:00:00Z","sessionId":"first","message":{"content":[{"type":"tool_result","tool_use_id":"later","content":[{"type":"text","text":"α😀\\\nquote\""},{"type":"image","source":{"data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"}}]}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Bash","input":{}}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Read","input":{"file_path":"/synthetic/workspace/docs/guide.md"}}]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z","attachment":{"filename":"MEMORY.md","content":"remember","addedBlocks":["",{"n":1.25,"b":true,"k":["é",null]}]}}
4
{"type":"user","timestamp":"2026-10-05T09:00:00Z","message":{"content":[{"type":"image"},{"type":"tool_result","content":[true,3,"",{"type":"unknown","x":"héllo"}]}]}}
{"type":"summary","timestamp":"2026-10-05T09:00:00Z","isCompactSummary":true}
{"type":"system","timestamp":"2026-10-05T09:00:00Z","subtype":"compact_boundary"}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"content":[]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z"}
{"type":"attachment","timestamp":"bad","ts":"2026-10-04T22:00:00Z","attachment":null}
{"type":"attachment","ts":"2026-10-04T22:00:00Z","sessionId":"final","attachment":{"filename":"notes.html","snippet":"html"}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"z","content":[]}}
{"type":"system","timestamp":"2026-10-05T09:00:00Z","isSidechain":true,"agentId":"worker"}"########.as_bytes().to_vec() });
    cases.push(Case { name: "claude-invalid-utf8", claude: true, exclude: false, repetitions: 1, bytes: { let mut b = r########"{"type":"user","timestamp":"2026-10-05T09:00:00Z","sessionId":"first","message":{"content":[{"type":"tool_result","tool_use_id":"later","content":[{"type":"text","text":"α😀\\\nquote\""},{"type":"image","source":{"data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"}}]}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Bash","input":{}}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Read","input":{"file_path":"/synthetic/workspace/docs/guide.md"}}]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z","attachment":{"filename":"MEMORY.md","content":"remember","addedBlocks":["",{"n":1.25,"b":true,"k":["é",null]}]}}
4
{"type":"user","timestamp":"2026-10-05T09:00:00Z","message":{"content":[{"type":"image"},{"type":"tool_result","content":[true,3,"",{"type":"unknown","x":"héllo"}]}]}}
{"type":"summary","timestamp":"2026-10-05T09:00:00Z","isCompactSummary":true}
{"type":"system","timestamp":"2026-10-05T09:00:00Z","subtype":"compact_boundary"}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"content":[]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z"}
{"type":"attachment","timestamp":"bad","ts":"2026-10-04T22:00:00Z","attachment":null}
{"type":"attachment","ts":"2026-10-04T22:00:00Z","sessionId":"final","attachment":{"filename":"notes.html","snippet":"html"}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"z","content":[]}}
"########.as_bytes().to_vec(); b.push(255); b } });
    cases.push(Case { name: "claude-out-of-window", claude: true, exclude: false, repetitions: 1, bytes: r########"{"type":"attachment","timestamp":"2025-01-01T00:00:00Z","attachment":{"content":"old"}}"########.as_bytes().to_vec() });
    cases.push(Case { name: "codex-adversarial", claude: false, exclude: false, repetitions: 1, bytes: r########"{"type":"session_meta","payload":{"session_id":"synthetic-codex"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call_output","call_id":"late","output":[{"type":"text","text":"é😀\\x"},{"type":"output_image","data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"},false]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call","call_id":"late","name":"read_file","arguments":"synthetic ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"late","name":"exec_command"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","message":"ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"rules"},{"type":"input_image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"text","text":"human excluded"},{"type":"image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"context_compacted"}}
{"type":"compacted","replacement_history":[{"text":"ignored"}]}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"web_search_end","query":"synthetic","results":[{"url":"https://example.invalid","score":2.5}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"browser","tool":"snapshot"},"result":{"Ok":{"content":[{"type":"text","text":"DOM"},{"type":"image"}],"other":"unused"}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"python","tool":"run"},"result":{"Ok":{"value":true}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","result":"ignored scalar"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call_output","call_id":"shell","output":{"type":"text","text":"shell"}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"shell"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","text":"end"}}
{"type":"session_meta","payload":{"id":"must-ignore-later"}}
{"partial":"########.as_bytes().to_vec() });
    cases.push(Case { name: "codex-invalid-utf8", claude: false, exclude: false, repetitions: 1, bytes: { let mut b = r########"{"type":"session_meta","payload":{"session_id":"synthetic-codex"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call_output","call_id":"late","output":[{"type":"text","text":"é😀\\x"},{"type":"output_image","data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"},false]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call","call_id":"late","name":"read_file","arguments":"synthetic ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"late","name":"exec_command"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","message":"ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"rules"},{"type":"input_image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"text","text":"human excluded"},{"type":"image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"context_compacted"}}
{"type":"compacted","replacement_history":[{"text":"ignored"}]}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"web_search_end","query":"synthetic","results":[{"url":"https://example.invalid","score":2.5}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"browser","tool":"snapshot"},"result":{"Ok":{"content":[{"type":"text","text":"DOM"},{"type":"image"}],"other":"unused"}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"python","tool":"run"},"result":{"Ok":{"value":true}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","result":"ignored scalar"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call_output","call_id":"shell","output":{"type":"text","text":"shell"}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"shell"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","text":"end"}}
{"type":"session_meta","payload":{"id":"must-ignore-later"}}
"########.as_bytes().to_vec(); b.push(255); b } });
    cases.push(Case { name: "codex-first-empty-meta", claude: false, exclude: false, repetitions: 1, bytes: r########"{"type":"session_meta"}
{"type":"session_meta","payload":{"session_id":"synthetic-codex"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call_output","call_id":"late","output":[{"type":"text","text":"é😀\\x"},{"type":"output_image","data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"},false]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call","call_id":"late","name":"read_file","arguments":"synthetic ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"late","name":"exec_command"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","message":"ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"rules"},{"type":"input_image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"text","text":"human excluded"},{"type":"image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"context_compacted"}}
{"type":"compacted","replacement_history":[{"text":"ignored"}]}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"web_search_end","query":"synthetic","results":[{"url":"https://example.invalid","score":2.5}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"browser","tool":"snapshot"},"result":{"Ok":{"content":[{"type":"text","text":"DOM"},{"type":"image"}],"other":"unused"}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"python","tool":"run"},"result":{"Ok":{"value":true}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","result":"ignored scalar"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call_output","call_id":"shell","output":{"type":"text","text":"shell"}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"shell"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","text":"end"}}
{"type":"session_meta","payload":{"id":"must-ignore-later"}}"########.as_bytes().to_vec() });
    cases.push(Case { name: "codex-mixed-content", claude: false, exclude: false, repetitions: 1, bytes: r########"{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"developer","content":["",null,false,2.1,{"type":"text","text":4},{"type":"unknown","key":"é"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message"}}"########.as_bytes().to_vec() });
    cases.push(Case { name: "codex-invalid-numeric-nesting", claude: false, exclude: false, repetitions: 1, bytes: r########"{"type":"session_meta","payload":{"session_id":"synthetic-codex"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call_output","call_id":"late","output":[{"type":"text","text":"é😀\\x"},{"type":"output_image","data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"},false]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"function_call","call_id":"late","name":"read_file","arguments":"synthetic ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"late","name":"exec_command"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","message":"ignored"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"rules"},{"type":"input_image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"text","text":"human excluded"},{"type":"image"}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"context_compacted"}}
{"type":"compacted","replacement_history":[{"text":"ignored"}]}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"web_search_end","query":"synthetic","results":[{"url":"https://example.invalid","score":2.5}]}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"browser","tool":"snapshot"},"result":{"Ok":{"content":[{"type":"text","text":"DOM"},{"type":"image"}],"other":"unused"}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","invocation":{"server":"python","tool":"run"},"result":{"Ok":{"value":true}}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"mcp_tool_call_end","result":"ignored scalar"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call_output","call_id":"shell","output":{"type":"text","text":"shell"}}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"shell"}}
{"timestamp":"2026-10-05T09:00:00Z","type":"response_item","payload":{"type":"agent_message","text":"end"}}
{"type":"session_meta","payload":{"id":"must-ignore-later"}}
{"type":"response_item","payload":{"type":"agent_message","ignored":1e999}}
{"type":"response_item","payload":{"type":"message","role":"developer","content":"valid tail"}}
[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
{"payload":{"type":"agent_message"}}"########.as_bytes().to_vec() });
    cases.push(Case { name: "claude-duplicate-keys", claude: true, exclude: false, repetitions: 1, bytes: r########"{"type":"user","timestamp":"2026-10-05T09:00:00Z","sessionId":"first","message":{"content":[{"type":"tool_result","tool_use_id":"later","content":[{"type":"text","text":"α😀\\\nquote\""},{"type":"image","source":{"data":"syntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsyntheticsynthetic"}}]}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Bash","input":{}}]}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"a","content":[{"type":"tool_use","id":"later","name":"Read","input":{"file_path":"/synthetic/workspace/docs/guide.md"}}]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z","attachment":{"filename":"MEMORY.md","content":"remember","addedBlocks":["",{"n":1.25,"b":true,"k":["é",null]}]}}
4
{"type":"user","timestamp":"2026-10-05T09:00:00Z","message":{"content":[{"type":"image"},{"type":"tool_result","content":[true,3,"",{"type":"unknown","x":"héllo"}]}]}}
{"type":"summary","timestamp":"2026-10-05T09:00:00Z","isCompactSummary":true}
{"type":"system","timestamp":"2026-10-05T09:00:00Z","subtype":"compact_boundary"}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"content":[]}}
{"type":"attachment","timestamp":"2026-10-05T09:00:00Z"}
{"type":"attachment","timestamp":"bad","ts":"2026-10-04T22:00:00Z","attachment":null}
{"type":"attachment","ts":"2026-10-04T22:00:00Z","sessionId":"final","attachment":{"filename":"notes.html","snippet":"html"}}
{"type":"assistant","timestamp":"2026-10-05T09:00:00Z","message":{"id":"z","content":[]}}
{"type":"attachment","attachment":{"content":"old","content":"new Unicode \u00e9"},"sessionId":"old","sessionId":"final"}
{"type":"assistant","message":{"id":"extra"}}"########.as_bytes().to_vec() });
    for claude in [true, false] {
        let row = |kind: &str, mut fields: serde_json::Map<String, Value>| {
            fields.insert("type".into(), json!(kind));
            if claude {
                fields.insert("timestamp".into(), json!("2026-10-05T09:00:00Z"));
                Value::Object(fields)
            } else {
                json!({"timestamp":"2026-10-05T09:00:00Z", "type":"response_item", "payload":fields})
            }
        };
        let object = |v: Value| v.as_object().unwrap().clone();
        let mut rows = Vec::new();
        for i in 0..500 {
            let id = i.to_string();
            if claude {
                rows.push(row("assistant", object(json!({"sessionId":"synthetic-large", "message":{"id":id,"content":[{"type":"text","text":"private-like synthetic ignored ".repeat(100)},{"type":"tool_use","id":id,"name":"Bash"}]}}))));
                rows.push(row("user", object(json!({"message":{"content":[{"type":"tool_result","tool_use_id":id,"content":[{"type":"text","text":"synthetic result ".repeat(30)},{"type":"image","data":"a".repeat(1024)}]}]}}))));
            } else {
                rows.push(row("function_call", object(json!({"call_id":id,"name":"exec_command","arguments":"synthetic ignored ".repeat(150)}))));
                rows.push(row("function_call_output", object(json!({"call_id":id,"output":[{"type":"text","text":"synthetic result ".repeat(30)},{"type":"image","data":"a".repeat(1024)}]}))));
            }
        }
        let encode = |rows: Vec<Value>| {
            rows.into_iter()
                .map(|r| serde_json::to_string(&r).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes()
        };
        cases.push(Case {
            name: if claude {
                "claude-code-representative"
            } else {
                "codex-representative"
            },
            claude,
            exclude: false,
            repetitions: 3,
            bytes: encode(rows),
        });
        let rows = if claude {
            vec![
                row(
                    "assistant",
                    object(
                        json!({"message":{"id":"big","content":[{"type":"text","text":"x".repeat(1_000_000)}]}}),
                    ),
                ),
                row(
                    "user",
                    object(
                        json!({"message":{"content":[{"type":"tool_result","content":[{"type":"image","data":"x".repeat(1_000_000)}]}]}}),
                    ),
                ),
                row("assistant", object(json!({"message":{"id":"after"}}))),
            ]
        } else {
            vec![
                row(
                    "agent_message",
                    object(json!({"text":"x".repeat(1_000_000)})),
                ),
                row(
                    "function_call_output",
                    object(json!({"output":[{"type":"image","data":"x".repeat(1_000_000)}]})),
                ),
                row("agent_message", Default::default()),
            ]
        };
        cases.push(Case {
            name: if claude {
                "claude-code-large-ignored-image"
            } else {
                "codex-large-ignored-image"
            },
            claude,
            exclude: false,
            repetitions: 3,
            bytes: encode(rows),
        });
    }
    assert_eq!(cases.len(), 15);
    cases
}
