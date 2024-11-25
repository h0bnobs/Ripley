import sqlite3
import unittest

class TestDatabase(unittest.TestCase):
    def setUp(self):
        # Create an in-memory SQLite database
        self.connection = sqlite3.connect(':memory:')
        self.cursor = self.connection.cursor()
        # Create the scan_results table
        self.cursor.execute('''
            create table scan_results
            (
                target           TEXT not null,
                host_output      TEXT,
                nmap_output      TEXT,
                smbclient_output TEXT,
                ftp_result       TEXT,
                screenshot       TEXT,
                robots_output    TEXT,
                scan_start_time  TIMESTAMP default CURRENT_TIMESTAMP,
                ai_advice        TEXT,
                scan_num         integer
                    constraint scan_results_pk
                        primary key autoincrement,
                subdomains_found TEXT,
                dns_recon_output TEXT,
                webpages_found   TEXT
            );
        ''')
        self.connection.commit()

    def tearDown(self):
        # Close the database connection
        self.connection.close()

    def test_insert_row(self):
        # Insert a row into the scan_results table
        self.cursor.execute('''
            INSERT INTO scan_results (target, scan_type, result) VALUES (?, ?, ?)
        ''', ('example.com', 'dns', 'No issues found'))
        self.connection.commit()

        # Query the row to verify it was inserted
        self.cursor.execute('SELECT * FROM scan_results WHERE target = ?', ('example.com',))
        row = self.cursor.fetchone()

        # Assert the row was inserted correctly
        self.assertIsNotNone(row)
        self.assertEqual(row[1], 'example.com')
        self.assertEqual(row[2], 'dns')
        self.assertEqual(row[3], 'No issues found')

if __name__ == '__main__':
    unittest.main()