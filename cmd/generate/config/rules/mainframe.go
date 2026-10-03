package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// RACF passwords are one to eight characters from A-Z, 0-9, @, # and $, and a real one is often a
// word with a digit, so these filters drop known placeholders rather than low entropy. A password
// phrase, or a password with any other character, is written in apostrophes.
const racfPlaceholder = `(?i)^(?:x+|\*+|y+|n+|pass|passw(?:or)?d?|pwd|secret|dummy|changeme|password|newpass(?:word)?|oldpass(?:word)?|&[A-Z0-9@#$]{1,8}\.?|(?:your[-_ ]?)?pass(?:word)?[-_ ]?phrase)$`

func MainframeJCLPassword() *config.Rule {
	r := config.Rule{
		ID:          "jcl-racf-password",
		Description: "Identified a RACF password or password phrase in a JCL statement, exposing the z/OS user ID it signs on.",
		Confidence:  "medium",
		Regex:       `(?im)^//[^*\n][^\n]*?\bPASSWORD=\(?(?:([A-Z0-9@#$]{1,8})(?:[,)'\s]|$)|'((?:[^'\n]|'')+)')`,
		Keywords:    []string{"password="},
		FilterExpr:  "matchesAny(finding[\"secret\"], [`" + racfPlaceholder + "`])",
	}

	tps := []string{
		`//PAYROLL  JOB (ACCT),'RUN',CLASS=A,MSGCLASS=X,USER=PAYADM,PASSWORD=K7QX2MPL`,
		`//NIGHTLY  JOB (ACCT),USER=BATCH01,PASSWORD=(Q9W8E7R6,Z1X2C3V4)`,
		`//STEP1    EXEC PGM=FTPXFER,PARM='USER=OPS,PASSWORD=M4INFR4M'`,
		`//payroll  job (acct),user=payadm,password=k7qx2mpl`,
		`//         PASSWORD='p9[Kz'`,                                            // special character, so in apostrophes
		`//PJOB     JOB (ACCT),'RUN',USER=PAYUSR,PASSWORD='Blue Heron Rides 42'`, // password phrase
		`//NJOB     JOB (ACCT),USER=AUSER,PASSWORD=(AUSER12,'Sm1th#x')`,          // old password
	}
	fps := []string{
		`//PAYROLL  JOB (ACCT),'RUN',CLASS=A,USER=&SYSUID,PASSWORD=&PW`, // symbolic parameter
		`//STEP0    JOB (ACCT),'RUN',PASSWORD=XXXXXXXX`,                 // placeholder
		`//* PASSWORD=K7QX2MPL mentioned in a comment line`,             // JCL comment
		`PASSWORD=K7QX2MPL`, // not a JCL statement
		`//STEP2    EXEC PGM=IEBGENER,PARM='PASSWORD=PASSWORD'`, // placeholder

		`//SYMJOB   JOB (ACCT),'RUN',USER=&SYSUID,PASSWORD='&PW'`,        // symbolic parameter in apostrophes
		`//PJOB     JOB (ACCT),'RUN',PASSWORD='your password phrase'`,    // placeholder
		`//* PASSWORD='Blue Heron Rides 42' mentioned in a comment line`, // JCL comment
	}
	return utils.Validate(r, tps, fps)
}

// A JOB card changes a password with PASSWORD=(old,new). jcl-racf-password reports the old one;
// this reports the new one, so each has its own finding and fingerprint.
func MainframeJCLNewPassword() *config.Rule {
	r := config.Rule{
		ID:          "jcl-racf-new-password",
		Description: "Identified a new RACF password or password phrase set in a JCL statement, exposing the z/OS user ID it signs on.",
		Confidence:  "medium",
		Regex:       `(?im)^//[^*\n][^\n]*?\bPASSWORD=\((?:[A-Z0-9@#$]{1,8}|'(?:[^'\n]|'')*'),(?:([A-Z0-9@#$]{1,8})\)|'((?:[^'\n]|'')+)'\))`,
		Keywords:    []string{"password="},
		FilterExpr:  "matchesAny(finding[\"secret\"], [`" + racfPlaceholder + "`])",
	}

	tps := []string{
		`//NIGHTLY  JOB (ACCT),USER=BATCH01,PASSWORD=(Q9W8E7R6,Z1X2C3V4)`,
		`//nightly  job (acct),user=batch01,password=(q9w8e7r6,z1x2c3v4),class=a`,
		`//NJOB     JOB (ACCT),USER=AUSER,PASSWORD=(AUSER12,'Sm1th#x')`,                          // new value in apostrophes
		`//PJOB     JOB (ACCT),USER=PAYUSR,PASSWORD=('Blue Heron Rides 42','Grey Owl Flies 17')`, // phrases
	}
	fps := []string{
		`//PAYROLL  JOB (ACCT),USER=PAYADM,PASSWORD=K7QX2MPL`,             // no new password
		`//NIGHTLY  JOB (ACCT),USER=BATCH01,PASSWORD=(&OLD,&NEW)`,         // symbolic parameters
		`//NIGHTLY  JOB (ACCT),USER=BATCH01,PASSWORD=(Q9W8E7R6,'&NEWPW')`, // symbolic parameter in apostrophes
		`//NIGHTLY  JOB (ACCT),USER=BATCH01,PASSWORD=(Q9W8E7R6,XXXXXXXX)`, // placeholder
		`//* PASSWORD=(Q9W8E7R6,Z1X2C3V4) mentioned in a comment line`,    // JCL comment
	}
	return utils.Validate(r, tps, fps)
}

func MainframeCOBOLValueCredential() *config.Rule {
	r := config.Rule{
		ID:          "cobol-value-credential",
		Description: "Identified a COBOL data item named for a credential with a literal VALUE, embedding the credential in the program.",
		Confidence:  "medium",
		// Column 7 holds the indicator: '*' or '/' makes the line a comment, and 'D' a debugging
		// line, which is still source. Levels 01-49 and 77 hold data; a level-88 condition name does
		// not. TOKEN alone in a COBOL name is usually a parser or SQL token, so only credential
		// tokens count. A literal may be hexadecimal, national, DBCS, null-terminated or UTF-8, and
		// one that runs to the end of its line continues on the next, so its first part is reported.
		// A hexadecimal value under four bytes is a flag, and one byte repeated is a fill.
		Regex:    `(?im)^(?:(?:[^*\n]{0,6}|[^*\n]{6}[^*/\n])\s*\b|[^*\n]{6}[Dd])(?:0?[1-9]|[1-4][0-9]|77)\s+[A-Z0-9-]*(?:PASSWORD|PASSWD|PASSWRD|PSWD|PWD|SECRET|APIKEY|API-KEY|ACCESS-KEY|(?:API|ACCESS|AUTH|BEARER|OAUTH|REFRESH)-?TOKEN)[A-Z0-9-]*\b[^.]*?\bVALUES?\s+(?:IS\s+|ARE\s+)?(?:NX|UX|[XNGZU])?(?:'([^'\n]{1,})(?:'|$)|"([^"\n]{1,})(?:"|$))`,
		Path:     `(?i)\.(?:cbl|cob|cobol|cpy|copy|sqb|pco|ccp)$`,
		Keywords: []string{"password", "passwd", "passwrd", "pswd", "pwd", "secret", "apikey", "api-key", "access-key", "token"},
		FilterExpr: "matchesAny(finding[\"secret\"], [`" +
			`(?i)^(?:x+|\*+|\s+|y|n|yes|no|true|false|on|off|[01]|pass(?:word)?|secret|dummy|changeme|password:?|enter.*|invalid.*|wrong.*|.*\S\s+\S.*)$` +
			"`]) || matchesAny(finding[\"match\"], [`" +
			`(?i)VALUES?\s+(?:IS\s+|ARE\s+)?(?:NX|UX|X)['"](?:[0-9A-F]{1,7}|0+|(?:40)+|(?:20)+|F+|(?:F0)+)['"]` +
			"`])",
	}

	tps := map[string]string{
		"login.cbl":   `       01 WS-DB-PASSWORD      PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,
		"api.cob":     `       01 WS-API-TOKEN        PIC X(20) VALUE "ghx8Kq2LmPz7Rt4Vw9Ys".`,
		"FTPPARM.CPY": `           05  FTP-PASSWD     PIC X(08) VALUE IS 'M4INFR4M'.`,
		"auth.cpy":    `           05  WS-AUTH-TOKEN  PIC X(20) VALUE 'q8Lm2Zp7Rt4Vw9YsKx3N'.`,
		"multi.cbl":   "       01 WS-DB-PASSWORD      PIC X(16)\n           VALUE 'Tr0ub4dor3xQz9'.",
		"hex.cpy":     `           05  WS-API-KEY     PIC X(8)  VALUE X'D7C1E2E2E6D6D9C4'.`,
		"cont.cpy":    "           05  WS-ACCESS-TOKEN PIC X(64) VALUE 'r7Kp2Lx9Qm4Tz8Wn3Vb6Y\n      -    'c1Hd5Jf0Gs2Ne7Ua4Mi9OkPl3Rq8StVw5Xy0Za2Bc4D'.",
		"debug.cbl":   `      D01  WS-DEBUG-PASSWORD   PIC X(8)  VALUE 'Dbg7Pw9Q'.`,
		"utf8.cbl":    `       01  WS-API-TOKEN        PIC U(8)  VALUE U'q8Lm2Zp7'.`,
	}
	fps := map[string]string{
		"a.cbl":     `       01 WS-DB-PASSWORD      PIC X(16) VALUE SPACES.`,                                           // figurative constant
		"b.cbl":     `       01 WS-PASSWORD-PROMPT  PIC X(20) VALUE 'Enter password:'.`,                                // prompt text
		"c.cbl":     `       01 WS-PASSWORD-MASK    PIC X(8)  VALUE '********'.`,                                       // mask
		"d.cbl":     `      *01 WS-OLD-PASSWORD     PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,                                 // comment line
		"login.txt": `       01 WS-DB-PASSWORD      PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,                                 // not COBOL source
		"e.cbl":     `       01 WS-CUSTOMER-NAME    PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,                                 // not a credential name
		"f.cbl":     `           88 PASSWORD-OK               VALUE 'Y'.`,                                              // condition name
		"g.cbl":     `              88 TOKEN-IS-CICS-RESERVED VALUE 'ABCODE'.`,                                         // condition name
		"h.cbl":     `     88 TOKEN-KEY VALUE '1'.`,                                                                    // free-format condition name
		"i.cbl":     `       01 WS-PASSWORD-STATE   PIC X     VALUE 'N'.`,                                              // flag value
		"j.cbl":     `           05 WS-TOKEN        PIC X(30) VALUE 'UNKNOWN'.`,                                        // parser token
		"k.cbl":     `       77 SQL-SYNTAX-TOKEN-MISSING PIC X(5) VALUE '37501'.`,                                      // SQLSTATE
		"m.cbl":     "       01 WS-PASSWORD-ERROR   PIC X(40)\n           VALUE \"Password must be 8-12 characters\".", // message text
		"l.cbl":     "       01 WS-PASSWORD-AREA.\n           05 WS-NAME PIC X(8) VALUE 'Tr0ub4do'.",                   // entry ends before the VALUE

		"n.cbl": `      / 01 WS-OLD-PASSWORD     PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,                                                               // comment line, new page
		"o.cbl": `       01 WS-PASSWORD-INIT    PIC X(8)  VALUE X'4040404040404040'.`,                                                             // EBCDIC spaces
		"p.cbl": `       01 WS-SECRET-NULLS     PIC X(8)  VALUE X'0000000000000000'.`,                                                             // zero fill
		"r.cbl": `       01 WS-PASSWORD-FLAG    PIC X     VALUE X'01'.`,                                                                           // one-byte flag
		"s.cbl": `       01 WS-PASSWORD-CHARS   PIC X(2)  VALUE X'C1C2'.`,                                                                         // two bytes
		"q.cbl": "       01 WS-PASSWORD-HELP    PIC X(80) VALUE 'Your password must be eig\n      -    'ht characters long and contain a digit'.", // continued message
	}
	return utils.ValidateWithPaths(r, tps, fps)
}

func MainframeEmbeddedSQLConnectPassword() *config.Rule {
	r := config.Rule{
		ID:          "embedded-sql-connect-password",
		Description: "Identified an embedded SQL CONNECT with a literal password, exposing the database user it signs on.",
		Confidence:  "medium",
		Regex:       `(?is)\bCONNECT\s+(?:TO\s+\S+\s+)?(?:USER\s+(?:'[^']*'|"[^"]*"|:?[A-Z0-9-]+)\s+USING|(?:(?:'[^']*'|"[^"]*"|:?[A-Z0-9-]+)\s+)?IDENTIFIED\s+BY)\s+(?:'([^'\n]{3,})'|"([^"\n]{3,})")`,
		Keywords:    []string{"connect"},
		FilterExpr: "matchesAny(finding[\"secret\"], [`" +
			`(?i)^(?:x+|\*+|pass(?:word)?|pwd|secret|dummy|changeme|your[-_ ]?password|<[^>]*>)$` +
			"`])",
	}

	tps := []string{
		`           EXEC SQL CONNECT TO SAMPLE USER 'DB2ADM' USING 'Pa55w0rdZ9q' END-EXEC.`,
		`           EXEC SQL CONNECT TO :DBNAME USER :WS-USER USING 'Pa55w0rdZ9q' END-EXEC.`,
		`           EXEC SQL CONNECT 'SCOTT' IDENTIFIED BY 'T1ger7Q2' END-EXEC.`,
		`           EXEC SQL CONNECT :USERNAME IDENTIFIED BY "T1ger7Q2" END-EXEC.`,
	}
	fps := []string{
		`           EXEC SQL CONNECT TO SAMPLE USER :WS-USER USING :WS-DB-PASSWORD END-EXEC.`, // host variables
		`           EXEC SQL CONNECT TO 'database' USER 'user' USING 'password' END-EXEC.`,    // placeholder
		`           EXEC SQL CONNECT :USERNAME IDENTIFIED BY :PASSWD END-EXEC.`,               // host variable
		`           EXEC SQL CONNECT TO SAMPLE END-EXEC.`,                                     // no credentials
	}
	return utils.Validate(r, tps, fps)
}
