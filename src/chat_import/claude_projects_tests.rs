//! Claude Projects (`projects.json`) import through the registry: standalone file,
//! export archive beside `conversations.json`, export folder, and malformed or empty input.

use std::fs;

use tempfile::tempdir;

use super::tests::build_zip;
use super::*;

const INSTRUCTIONS: &str = "You are the Gusto payroll reviewer.\n\nAlways cite the pay period.";
const HANDBOOK: &str = "# Payroll handbook\n\nRun payroll on the 15th.\n";

fn projects_json() -> String {
    serde_json::json!([
        {
            "uuid": "proj-1",
            "name": "Gusto Payroll",
            "description": "Everything about running payroll.",
            "is_private": true,
            "is_starter_project": false,
            "prompt_template": INSTRUCTIONS,
            "created_at": "2026-11-01T09:00:00Z",
            "updated_at": "2026-11-05T09:00:00Z",
            "creator": { "uuid": "user-1", "full_name": "Tommie" },
            "docs": [
                { "uuid": "doc-1", "filename": "handbook.md", "content": HANDBOOK, "created_at": "2026-11-02T09:00:00Z" },
                { "uuid": "doc-2", "filename": "empty.txt", "content": "", "created_at": "2026-11-03T09:00:00Z" }
            ]
        },
        {
            "uuid": "proj-empty",
            "name": "Nothing Inside",
            "description": "",
            "prompt_template": "",
            "created_at": "2026-11-01T09:00:00Z",
            "updated_at": "2026-11-01T09:00:00Z",
            "docs": []
        }
    ])
    .to_string()
}

fn conversations_json() -> String {
    serde_json::json!([{
        "uuid": "cl-1",
        "name": "Payroll question",
        "created_at": "2026-11-10T14:30:00Z",
        "updated_at": "2026-11-10T14:35:00Z",
        "chat_messages": [
            { "sender": "human", "text": "When do we run payroll?", "created_at": "2026-11-10T14:30:05Z" },
            { "sender": "assistant", "content": [{ "type": "text", "text": "On the 15th." }], "created_at": "2026-11-10T14:31:00Z" }
        ]
    }])
    .to_string()
}

fn assert_gusto_project(project: &ImportedConversation) {
    assert_eq!(project.source_id, "claude_export:project:proj-1");
    assert_eq!(project.adapter_id, "claude_export");
    assert_eq!(project.participants, ["owner"]);
    assert_eq!(project.title, "Gusto Payroll");
    assert_eq!(project.created_at, 1_793_523_600);
    assert_eq!(project.updated_at, 1_793_869_200);
    let turns: Vec<(&str, &str, u64)> = project
        .turns
        .iter()
        .map(|t| (t.role.as_str(), t.content.as_str(), t.timestamp))
        .collect();
    assert_eq!(
        turns,
        vec![
            (
                "user",
                "Project description\n\nEverything about running payroll.",
                1_793_523_600
            ),
            (
                "user",
                "Project instructions\n\nYou are the Gusto payroll reviewer.\n\nAlways cite the pay period.",
                1_793_523_600
            ),
            (
                "user",
                "Project knowledge: handbook.md\n\n# Payroll handbook\n\nRun payroll on the 15th.\n",
                1_793_610_000
            ),
        ]
    );
}

#[test]
fn standalone_projects_json_is_detected_and_imported() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("projects.json");
    fs::write(&path, projects_json()).expect("write projects.json");
    let reg = ChatImportRegistry::builtin();

    let (detected, score) = reg.detect(&path).expect("detect projects.json");
    assert_eq!(detected.descriptor().adapter_id, "claude_export");
    assert_eq!(score, 95);

    let inventory = reg
        .scan_adapter("claude_export", Some(&path), None)
        .expect("scan projects.json");
    assert_eq!(inventory.conversation_count, 1);
    assert_eq!(inventory.conversations[0].title, "Gusto Payroll");
    assert_eq!(inventory.conversations[0].message_count, 3);
    assert_eq!(inventory.conversations[0].user_message_count, 3);
    assert_eq!(
        inventory.conversations[0].preview,
        "Project description Everything about running payroll."
    );

    let loaded = reg
        .load_conversations("claude_export", Some(&path), None, None)
        .expect("load projects.json");
    assert_eq!(loaded.len(), 1);
    assert_gusto_project(&loaded[0]);
}

#[test]
fn export_archive_and_folder_import_projects_beside_conversations() {
    let dir = tempdir().expect("tempdir");
    let reg = ChatImportRegistry::builtin();
    let (projects, conversations) = (projects_json(), conversations_json());

    let archive = dir.path().join("claude-export.zip");
    fs::write(
        &archive,
        build_zip(
            &[
                ("users.json", b"[]".as_slice()),
                ("projects.json", projects.as_bytes()),
                ("conversations.json", conversations.as_bytes()),
            ],
            true,
        ),
    )
    .expect("write archive");
    let folder = dir.path().join("claude-export");
    fs::create_dir(&folder).expect("create folder");
    fs::write(folder.join("projects.json"), &projects).expect("write projects.json");
    fs::write(folder.join("conversations.json"), &conversations).expect("write conversations");

    for (source, expected_score) in [(&archive, 96), (&folder, 95)] {
        let (detected, score) = reg.detect(source).expect("detect export");
        assert_eq!(detected.descriptor().adapter_id, "claude_export");
        assert_eq!(score, expected_score);

        let loaded = reg
            .load_conversations("claude_export", Some(source), None, None)
            .expect("load export");
        let ids: Vec<&str> = loaded.iter().map(|c| c.source_id.as_str()).collect();
        assert_eq!(ids, ["claude_export:cl-1", "claude_export:project:proj-1"]);
        assert_eq!(loaded[0].message_count, 2);
        assert_eq!(loaded[0].turns[1].content, "On the 15th.");
        assert_gusto_project(&loaded[1]);
    }

    let only_projects = dir.path().join("only-projects.zip");
    fs::write(
        &only_projects,
        build_zip(&[("export/projects.json", projects.as_bytes())], false),
    )
    .expect("write projects archive");
    assert_eq!(reg.detect(&only_projects).expect("detect").1, 96);
    let selected = HashSet::from(["claude_export:project:proj-1".to_string()]);
    let loaded = reg
        .load_conversations("claude_export", Some(&only_projects), None, Some(&selected))
        .expect("load projects archive");
    assert_eq!(loaded.len(), 1);
    assert_gusto_project(&loaded[0]);
}

#[test]
fn malformed_and_empty_projects_json_never_invent_projects() {
    let dir = tempdir().expect("tempdir");
    let reg = ChatImportRegistry::builtin();
    let load = |name: &str, body: &str| {
        let path = dir.path().join(name);
        fs::write(&path, body).expect("write");
        reg.load_conversations("claude_export", Some(&path), None, None)
    };

    assert_eq!(load("empty-array.json", "[]"), Ok(Vec::new()));
    assert_eq!(
        load(
            "wrong-types.json",
            r#"[7, "x", null, {"docs": "none"}, {"prompt_template": 3, "docs": [4, {"content": 5}]}]"#
        ),
        Ok(Vec::new())
    );
    let truncated = load(
        "truncated.json",
        r#"[{"uuid": "proj-1", "prompt_template": "Be"#,
    );
    assert!(
        truncated
            .expect_err("truncated JSON")
            .starts_with("parsing Claude export JSON:")
    );

    let nameless = load(
        "nameless.json",
        r#"[{"prompt_template": "Answer in French.", "docs": [{"content": "Bonjour"}]}]"#,
    )
    .expect("load nameless project");
    assert_eq!(nameless.len(), 1);
    assert_eq!(nameless[0].title, "Claude Project");
    assert!(nameless[0].source_id.starts_with("claude_export:project:"));
    assert_eq!(
        nameless[0].turns[1].content,
        "Project knowledge: Untitled\n\nBonjour"
    );
    assert_eq!(
        load(
            "nameless-again.json",
            r#"[{"prompt_template": "Answer in French.", "docs": [{"content": "Bonjour"}]}]"#
        )
        .expect("reload")[0]
            .source_id,
        nameless[0].source_id
    );

    let docs_only = dir.path().join("docs-only.json");
    fs::write(
        &docs_only,
        r#"[{"id": "proj-2", "docs": [{"filename": " notes.md ", "content": "Net 30.", "updated_at": "2026-11-02T09:00:00Z"}]}]"#,
    )
    .expect("write docs-only");
    assert!(
        reg.detect(&docs_only).is_none(),
        "an id is not a Claude uuid"
    );
    fs::write(
        &docs_only,
        r#"[{"uuid": "proj-2", "docs": [{"filename": " notes.md ", "content": "Net 30.", "updated_at": "2026-11-02T09:00:00Z"}]}]"#,
    )
    .expect("write docs-only");
    assert_eq!(reg.detect(&docs_only).expect("detect docs-only").1, 95);
    let loaded = reg
        .load_conversations("claude_export", Some(&docs_only), None, None)
        .expect("load docs-only");
    assert_eq!(loaded[0].source_id, "claude_export:project:proj-2");
    assert_eq!(
        loaded[0].turns[0].content,
        "Project knowledge: notes.md\n\nNet 30."
    );
    assert_eq!(loaded[0].turns[0].timestamp, 1_793_610_000);

    let unrelated = dir.path().join("prompt-config.json");
    fs::write(&unrelated, r#"{"prompt_template": "Hello {name}"}"#).expect("write config");
    assert!(reg.detect(&unrelated).is_none());

    let broken_archive = dir.path().join("broken.zip");
    fs::write(
        &broken_archive,
        build_zip(
            &[
                ("conversations.json", conversations_json().as_bytes()),
                ("projects.json", b"{not json".as_slice()),
            ],
            true,
        ),
    )
    .expect("write broken archive");
    let error = reg
        .load_conversations("claude_export", Some(&broken_archive), None, None)
        .expect_err("malformed projects.json fails the import instead of dropping projects");
    assert!(error.starts_with("parsing Claude export JSON:"));
}
