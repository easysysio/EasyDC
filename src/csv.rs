//! Reading and writing CSV (RFC 4180), as spreadsheets save it: fields in
//! double quotes when they hold a separator, a quote or a line break, a quote
//! inside one written twice.

/// Start a file a spreadsheet opens as UTF-8: Excel reads a file without this
/// mark in the computer's own code page, which garbles names such as "Müller".
pub const BOM: &str = "\u{feff}";

/// Characters a spreadsheet reads as the start of a formula. A value from
/// the directory beginning with one (a phone number a user set to
/// `=HYPERLINK(…)`, say) is written with a `'` in front, so opening the
/// export runs nothing; [`parse`] takes the `'` off again.
const FORMULA_START: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Add one row, ending in CRLF as RFC 4180 has it.
pub fn write_row<S: AsRef<str>>(out: &mut String, fields: &[S]) {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut value = field.as_ref().to_string();
        if value.starts_with(FORMULA_START) {
            value.insert(0, '\'');
        }
        if value.contains([',', '"', '\r', '\n']) || value != value.trim() {
            out.push('"');
            out.push_str(&value.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(&value);
        }
    }
    out.push_str("\r\n");
}

/// One row read from a file, with the line it starts on (1 for the first).
#[derive(Debug, PartialEq)]
pub struct Record {
    pub line: usize,
    pub fields: Vec<String>,
}

/// Read a whole file. The separator is a comma, or what the first line uses
/// instead: Excel saves with `;` where a comma is the decimal point, and some
/// tools with a tab. Empty lines are skipped.
pub fn parse(text: &str) -> Result<Vec<Record>, String> {
    let text = text.strip_prefix(BOM).unwrap_or(text);
    let sep = separator(text);
    let mut records = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    // Whether the field was quoted: a quoted empty field is still a field.
    let mut quoted = false;
    let mut in_quotes = false;
    let mut line = 1;
    let mut start = 1;
    let mut chars = text.chars().peekable();

    let end_field = |fields: &mut Vec<String>, field: &mut String, quoted: &mut bool| {
        let mut value = std::mem::take(field);
        if !*quoted {
            value = value.trim().to_string();
        }
        if value.starts_with('\'') && value[1..].starts_with(FORMULA_START) {
            value.remove(0);
        }
        fields.push(value);
        *quoted = false;
    };

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => in_quotes = false,
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                '\r' if chars.peek() == Some(&'\n') => {}
                c => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.trim().is_empty() && !quoted => {
                field.clear();
                quoted = true;
                in_quotes = true;
            }
            '"' => return Err(format!("Line {line}: a quote in the middle of a field; put the whole field in quotes and write the quote twice")),
            c if c == sep => end_field(&mut fields, &mut field, &mut quoted),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\r' | '\n' => {
                end_field(&mut fields, &mut field, &mut quoted);
                if !(fields.len() == 1 && fields[0].is_empty()) {
                    records.push(Record { line: start, fields: std::mem::take(&mut fields) });
                }
                fields.clear();
                line += 1;
                start = line;
            }
            c if quoted => {
                if !c.is_whitespace() {
                    return Err(format!("Line {line}: text after a field's closing quote"));
                }
            }
            c => field.push(c),
        }
    }
    if in_quotes {
        return Err(format!("Line {start}: a quoted field is not closed"));
    }
    if !field.is_empty() || quoted || !fields.is_empty() {
        end_field(&mut fields, &mut field, &mut quoted);
        if !(fields.len() == 1 && fields[0].is_empty()) {
            records.push(Record { line: start, fields });
        }
    }
    Ok(records)
}

/// The separator the first line uses, outside quotes: a comma unless it has
/// none and has a semicolon or a tab.
fn separator(text: &str) -> char {
    let mut in_quotes = false;
    let (mut commas, mut semicolons, mut tabs) = (0, 0, 0);
    for c in text.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\n' | '\r' if !in_quotes => break,
            ',' if !in_quotes => commas += 1,
            ';' if !in_quotes => semicolons += 1,
            '\t' if !in_quotes => tabs += 1,
            _ => {}
        }
    }
    if commas > 0 {
        ','
    } else if semicolons >= tabs && semicolons > 0 {
        ';'
    } else if tabs > 0 {
        '\t'
    } else {
        ','
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str) -> Vec<Vec<String>> {
        parse(text).unwrap().into_iter().map(|r| r.fields).collect()
    }

    #[test]
    fn fields_that_need_quotes_get_them() {
        let mut out = String::new();
        write_row(&mut out, &["plain", "a,b", "say \"hi\"", "two\nlines", " padded", ""]);
        assert_eq!(out, "plain,\"a,b\",\"say \"\"hi\"\"\",\"two\nlines\",\" padded\",\r\n");
    }

    #[test]
    fn what_is_written_reads_back_the_same() {
        let values = ["Müller", "a,b", "say \"hi\"", "two\r\nlines", " padded ", "", "=SUM(A1)", "+972 3 555", "-", "@x"];
        let mut out = String::from(BOM);
        write_row(&mut out, &values);
        write_row(&mut out, &["second"]);
        let back = rows(&out);
        assert_eq!(back[0], values.iter().map(|v| v.replace("\r\n", "\n")).collect::<Vec<_>>());
        assert_eq!(back[1], vec!["second"]);
    }

    #[test]
    fn a_formula_is_not_written_as_one() {
        let mut out = String::new();
        write_row(&mut out, &["=HYPERLINK(\"http://x\")", "+1", "@SUM(A1)", "-2", "ok"]);
        assert!(out.starts_with("\"'=HYPERLINK("), "{out}");
        assert!(out.contains(",'+1,'@SUM(A1),'-2,ok"), "{out}");
    }

    #[test]
    fn excel_files_read_in_every_separator() {
        assert_eq!(rows("a,b\r\n1,2\r\n"), vec![vec!["a", "b"], vec!["1", "2"]]);
        assert_eq!(rows("a;b\n1;\"2;3\"\n"), vec![vec!["a", "b"], vec!["1", "2;3"]]);
        assert_eq!(rows("a\tb\n1\t2"), vec![vec!["a", "b"], vec!["1", "2"]]);
        // A semicolon inside a comma file is just text.
        assert_eq!(rows("a,b\nx;y,z"), vec![vec!["a", "b"], vec!["x;y", "z"]]);
    }

    #[test]
    fn spaces_around_fields_and_empty_lines_are_dropped() {
        assert_eq!(rows("\n a , b \n\n\r\n c ,\" d \"\n"), vec![vec!["a", "b"], vec!["c", " d "]]);
        assert_eq!(rows("a,,\"\""), vec![vec!["a", "", ""]]);
    }

    #[test]
    fn records_know_their_line() {
        let r = parse("h\n\"two\nlines\"\nthird\n").unwrap();
        assert_eq!(r.iter().map(|r| r.line).collect::<Vec<_>>(), vec![1, 2, 4]);
    }

    #[test]
    fn broken_quotes_are_refused_with_the_line() {
        assert!(parse("a\n\"open").unwrap_err().starts_with("Line 2:"));
        assert!(parse("a\nx\"y").unwrap_err().contains("in the middle"));
        assert!(parse("\"a\"b").unwrap_err().contains("after a field's closing quote"));
    }
}
