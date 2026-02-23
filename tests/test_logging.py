import logging
import os
import sys
from unittest.mock import MagicMock

os.environ["DATABASE_URL"] = "postgres://test:test@localhost:5432/testdb"
os.environ["MCP_ALLOW_WRITE"] = "false"
sys.modules["psycopg_pool"] = MagicMock()

import server


def test_run_query_logging(mocker):
        tool_obj = server.db_pg96_run_query
        func = getattr(tool_obj, "fn", getattr(tool_obj, "func", None))
        assert func is not None, "Could not find underlying function on Tool object."

        mock_info = mocker.patch.object(server.logger, "info")
        mock_debug = mocker.patch.object(server.logger, "debug")
        mocker.patch("server._require_readonly", return_value=True)
        mock_pool = mocker.patch("server.pool")

        mock_conn = MagicMock()
        mock_pool.connection.return_value.__enter__.return_value = mock_conn

        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.description = [
            ("id", 23, None, 4, None, None, None),
            ("name", 25, None, -1, None, None, None),
        ]
        mock_cursor.fetchmany.side_effect = [[{"id": 1, "name": "a"}], []]

        func("SELECT * FROM users", params_json='{"id": 1}', max_rows=1)

        assert mock_info.called, "logger.info should have been called"
        info_msg = mock_info.call_args.args[0]
        assert "SELECT * FROM users" not in info_msg
        assert "sql_len=" in info_msg
        assert "sql_sha256=" in info_msg

        assert mock_debug.called, "logger.debug should have been called"
        debug_msg = mock_debug.call_args.args[0]
        assert '{"id": 1}' not in debug_msg
        assert "params_sha256=" in debug_msg

        assert mock_cursor.fetchmany.call_count >= 1



