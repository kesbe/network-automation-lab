from pathlib import Path

MIGRATION = Path(
    "db/migrations/007_stale_reconciliation_security.sql"
).read_text()

PLAYBOOK = Path(
    "playbooks/transport_reconcile.yml"
).read_text()


def test_reconciler_roles_are_separate():
    assert "compliance_reconciler" in MIGRATION
    assert "compliance_reconciler_runtime" in MIGRATION
    assert "GRANT compliance_reconciler" in MIGRATION


def test_reconciler_has_controlled_stale_read_api():
    assert "inspect_stale_transport_event" in MIGRATION
    assert "'STALE_CANDIDATE'" in MIGRATION
    assert "state <> 'CLAIMED'" in MIGRATION
    assert "lease_expires_at > v_now" in MIGRATION


def test_reconciler_can_reclaim():
    assert "reclaim_stale_transport_event" in MIGRATION
    assert "TO compliance_reconciler;" in MIGRATION


def test_normal_transport_roles_cannot_reclaim():
    assert (
        "FROM compliance_ingest;"
        in MIGRATION
    )
    assert (
        "FROM compliance_writer;"
        in MIGRATION
    )


def test_reconciler_has_no_raw_transport_table_grant():
    forbidden = (
        "GRANT SELECT ON TABLE compliance.transport_events "
        "TO compliance_reconciler"
    )
    assert forbidden not in MIGRATION

    assert (
        "REVOKE ALL PRIVILEGES"
        in MIGRATION
    )


def test_playbook_requires_dedicated_db_runtime_role():
    assert (
        "pg_username == 'compliance_reconciler_runtime'"
        in PLAYBOOK
    )


def test_playbook_requires_production_wrapper_provenance():
    assert (
        "production_transport_workflow_template_id: 56"
        in PLAYBOOK
    )

    assert (
        "workflow_job_template | int "
        "== production_transport_workflow_template_id"
        in PLAYBOOK
    )


def test_only_failure_terminal_states_are_eligible():
    assert "- failed" in PLAYBOOK
    assert "- error" in PLAYBOOK
    assert "- canceled" in PLAYBOOK

    allowed_section = PLAYBOOK.split(
        "safe_previous_workflow_terminal_states:"
    )[1].split("tasks:")[0]

    assert "successful" not in allowed_section
    assert "running" not in allowed_section
    assert "pending" not in allowed_section
    assert "waiting" not in allowed_section


def test_current_recovery_workflow_becomes_new_owner():
    assert (
        "new_workflow_job_id: "
        '"{{ awx_workflow_job_id | int }}"'
        in PLAYBOOK
    )


def test_playbook_requires_claimed_reconciled():
    assert (
        "transport_reclaim_result.decision "
        "== 'CLAIMED_RECONCILED'"
        in PLAYBOOK
    )


def test_awx_token_is_not_hard_coded():
    assert "NETAUTO_AWX_TOKEN" in PLAYBOOK
    assert "Authorization: \"Bearer {{ awx_api_token }}\"" in PLAYBOOK
