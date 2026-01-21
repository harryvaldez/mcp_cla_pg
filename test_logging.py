import logging
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

os.environ["DATABASE_URL"] = "postgres://test:test@localhost:5432/testdb"
os.environ["MCP_ALLOW_WRITE"] = "false"
sys.modules["psycopg_pool"] = MagicMock()

import server


class TestRunQueryLogging(unittest.TestCase):
    def setUp(self) -> None:
        self.root_logger = logging.getLogger()
        self.stream_handler = logging.StreamHandler(sys.stdout)
        self.root_logger.addHandler(self.stream_handler)

    def tearDown(self) -> None:
        self.root_logger.removeHandler(self.stream_handler)

    def test_run_query_logging(self) -> None:
        tool_obj = server.run_query
        func = getattr(tool_obj, "fn", getattr(tool_obj, "func", None))
        self.assertIsNotNone(func, "Could not find underlying function on Tool object.")

        with patch.object(server.logger, "info") as mock_info, patch.object(
            server.logger, "debug"
        ) as mock_debug:
            with patch("server._require_readonly", return_value=True), patch(
                "server.pool"
            ) as mock_pool:
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

                self.assertTrue(mock_info.called, "logger.info should have been called")
                info_msg = mock_info.call_args.args[0]
                self.assertNotIn("SELECT * FROM users", info_msg)
                self.assertIn("sql_len=", info_msg)
                self.assertIn("sql_sha256=", info_msg)

                self.assertTrue(mock_debug.called, "logger.debug should have been called")
                debug_msg = mock_debug.call_args.args[0]
                self.assertNotIn('{"id": 1}', debug_msg)
                self.assertIn("params_sha256=", debug_msg)

                self.assertGreaterEqual(mock_cursor.fetchmany.call_count, 1)


if __name__ == "__main__":
    unittest.main()
