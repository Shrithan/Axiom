use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub struct AdminState {
    pub rules: Mutex<Vec<PolicyRule>>,
    pub employees: Mutex<Vec<Employee>>,
}

impl Default for AdminState {
    fn default() -> Self {
        Self {
            rules: Mutex::new(default_rules()),
            employees: Mutex::new(default_employees()),
        }
    }
}

fn init_shared_db() -> rusqlite::Result<rusqlite::Connection> {
    let db_path = std::env::temp_dir().join("axiom_shared.db");
    let conn = rusqlite::Connection::open(db_path)?;
    
    // Activity Log Table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS activity_log (
            id TEXT PRIMARY KEY, employee_name TEXT, department TEXT, file_name TEXT,
            detection_count INTEGER, highest_severity TEXT, timestamp INTEGER, redacted BOOLEAN, pii_types TEXT
        )", [],
    )?;

    // Employees Table (NEW)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS employees (
            id TEXT PRIMARY KEY, name TEXT, username TEXT UNIQUE, password TEXT,
            department TEXT, status TEXT, last_seen INTEGER, total_scans INTEGER,
            total_detections INTEGER, risk_score INTEGER, avatar_initials TEXT
        )", [],
    )?;

    // Create a default admin user if the table is empty
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM employees", [], |row| row.get(0))?;
    if count == 0 {
        let _ = conn.execute(
            "INSERT INTO employees (id, name, username, password, department, status, last_seen, total_scans, total_detections, risk_score, avatar_initials)
             VALUES ('e_admin', 'Admin User', 'admin', 'password', 'IT', 'active', 0, 0, 0, 0, 'AD')", []
        );
    }
    
    Ok(conn)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Employee {
    pub id: String,
    pub name: String,
    pub email: String,
    pub department: String,
    pub status: String,
    pub last_seen: u64,
    pub total_scans: u32,
    pub total_detections: u32,
    pub risk_score: u8,
    pub avatar_initials: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLog {
    pub id: String,
    pub employee_id: String,
    pub employee_name: String,
    pub department: String,
    pub file_name: String,
    pub detection_count: u32,
    pub highest_severity: String,
    pub timestamp: u64,
    pub redacted: bool,
    pub pii_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub severity: String,
    pub enabled: bool,
    pub detection_count: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmployeePatch {
    pub status: Option<String>,
    pub department: Option<String>,
}

// ─── ISOLATED COMMANDS MODULE ──────────────────────────────────────────
pub mod commands {
    use super::*; // Pulls in the structs and state defined above
    use tauri::State;

    #[tauri::command]
    pub fn list_employees() -> Vec<Employee> {
        let conn = match init_shared_db() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
    
        let mut stmt = conn.prepare("SELECT id, name, username, department, status, last_seen, total_scans, total_detections, risk_score, avatar_initials FROM employees").unwrap();
        let iter = stmt.query_map([], |row| {
            Ok(Employee {
                id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?, // Using email field for username
                department: row.get(3)?,
                status: row.get(4)?,
                last_seen: row.get(5)?,
                total_scans: row.get(6)?,
                total_detections: row.get(7)?,
                risk_score: row.get(8)?,
                avatar_initials: row.get(9)?,
            })
        }).unwrap();
    
        iter.filter_map(Result::ok).collect()
    }

    #[tauri::command]
    pub fn add_employee(name: String, username: String, pass: String, dept: String) -> Result<(), String> {
        // 1. Log that the frontend successfully reached the backend
        println!("\n[DEBUG] === ADD EMPLOYEE COMMAND TRIGGERED ===");
        println!("[DEBUG] Received -> Name: '{}', Username: '{}', Dept: '{}'", name, username, dept);
    
        // 2. Try connecting to the database
        let conn = match init_shared_db() {
            Ok(c) => {
                println!("[DEBUG] Successfully connected to axiom_shared.db");
                c
            },
            Err(e) => {
                println!("[ERROR] Failed to initialize DB: {}", e);
                return Err(format!("Database connection failed: {}", e));
            }
        };
    
        let id = format!("e_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        let initials = name.split_whitespace().map(|s| s.chars().next().unwrap_or(' ')).take(2).collect::<String>().to_uppercase();
        
        println!("[DEBUG] Generated Employee ID: {}", id);
    
        // 3. Attempt the insertion
        let result = conn.execute(
            "INSERT INTO employees (id, name, username, password, department, status, last_seen, total_scans, total_detections, risk_score, avatar_initials)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![id, name, username, pass, dept, "active", 0, 0, 0, 0, initials]
        );
    
        // 4. Check the result and print exactly what happened
        match result {
            Ok(rows_inserted) => {
                println!("[DEBUG] SUCCESS: Inserted {} row(s) into employees table.\n", rows_inserted);
                Ok(())
            },
            Err(e) => {
                println!("[ERROR] SQL INSERT FAILED: {}\n", e);
                Err(format!("SQL Error: {}", e))
            }
        }
    }

    #[tauri::command]
    pub fn update_employee(id: String, patch: EmployeePatch, state: State<'_, AdminState>) -> Result<Employee, String> {
        let mut employees = state.employees.lock().unwrap();
        let emp = employees.iter_mut().find(|e| e.id == id)
            .ok_or_else(|| format!("Employee {} not found", id))?;
        if let Some(status) = patch.status { emp.status = status; }
        if let Some(dept) = patch.department { emp.department = dept; }
        Ok(emp.clone())
    }

    #[tauri::command]
    pub fn remove_employee(id: String, state: State<'_, AdminState>) -> Result<(), String> {
        let mut employees = state.employees.lock().unwrap();
        let before = employees.len();
        employees.retain(|e| e.id != id);
        if employees.len() == before { Err(format!("Employee {} not found", id)) } else { Ok(()) }
    }

    // Replace your existing list_activity command with this:
    #[tauri::command]
    pub fn list_activity(employee_id: Option<String>) -> Vec<ActivityLog> {
        let db_path = std::env::temp_dir().join("axiom_shared.db");
        
        let conn = match rusqlite::Connection::open(&db_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(), // Return empty if DB doesn't exist yet
        };
    
        let mut stmt = match conn.prepare("SELECT id, employee_name, department, file_name, detection_count, highest_severity, timestamp, redacted, pii_types FROM activity_log ORDER BY timestamp DESC") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
    
        let log_iter = stmt.query_map([], |row| {
            let pii_str: String = row.get(8)?;
            Ok(ActivityLog {
                id: row.get(0)?,
                employee_id: "e1".into(), // Mocked ID to match the Demo Employee
                employee_name: row.get(1)?,
                department: row.get(2)?,
                file_name: row.get(3)?,
                detection_count: row.get(4)?,
                highest_severity: row.get(5)?,
                timestamp: row.get(6)?,
                redacted: row.get(7)?,
                pii_types: pii_str.split(';').map(|s| s.to_string()).filter(|s| !s.is_empty()).collect(),
            })
        });
    
        let mut all_logs: Vec<ActivityLog> = match log_iter {
            Ok(iter) => iter.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        };
    
        // Apply the employee filter if an ID was passed in
        if let Some(id) = employee_id {
            all_logs.retain(|log| log.employee_id == id);
        }
    
        all_logs
    }

    #[tauri::command]
    pub fn export_activity_csv(employee_id: Option<String>) -> String {
        let logs = list_activity(employee_id);
        let mut csv = String::from("id,employee_id,employee_name,department,file_name,detection_count,highest_severity,timestamp,redacted,pii_types\n");
        for l in logs {
            csv.push_str(&format!("{},{},{},{},{},{},{},{},{},{}\n",
                l.id, l.employee_id, l.employee_name, l.department, l.file_name,
                l.detection_count, l.highest_severity, l.timestamp, l.redacted, l.pii_types.join(";")));
        }
        csv
    }

    #[tauri::command]
    pub fn list_rules(state: State<'_, AdminState>) -> Vec<PolicyRule> {
        state.rules.lock().unwrap().clone()
    }

    #[tauri::command]
    pub fn toggle_rule(id: String, state: State<'_, AdminState>) -> Result<PolicyRule, String> {
        let mut rules = state.rules.lock().unwrap();
        let rule = rules.iter_mut().find(|r| r.id == id)
            .ok_or_else(|| format!("Rule {} not found", id))?;
        rule.enabled = !rule.enabled;
        Ok(rule.clone())
    }

    #[tauri::command]
    pub fn set_rule_severity(id: String, severity: String, state: State<'_, AdminState>) -> Result<PolicyRule, String> {
        let valid = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        if !valid.contains(&severity.as_str()) { return Err(format!("Invalid severity: {}", severity)); }
        let mut rules = state.rules.lock().unwrap();
        let rule = rules.iter_mut().find(|r| r.id == id)
            .ok_or_else(|| format!("Rule {} not found", id))?;
        rule.severity = severity;
        Ok(rule.clone())
    }

    #[tauri::command]
    pub fn add_rule(rule: PolicyRule, state: State<'_, AdminState>) -> Result<PolicyRule, String> {
        let mut rules = state.rules.lock().unwrap();
        if rules.iter().any(|r| r.id == rule.id) { return Err(format!("Rule id {} already exists", rule.id)); }
        rules.push(rule.clone());
        Ok(rule)
    }

    #[tauri::command]
    pub fn delete_rule(id: String, state: State<'_, AdminState>) -> Result<(), String> {
        let mut rules = state.rules.lock().unwrap();
        let before = rules.len();
        rules.retain(|r| r.id != id);
        if rules.len() == before { Err(format!("Rule {} not found", id)) } else { Ok(()) }
    }
}
// ───────────────────────────────────────────────────────────────────────────────



pub fn run() {
    tauri::Builder::default()
        .manage(AdminState::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            // Note the `commands::` prefix here
            commands::list_employees, 
            commands::update_employee, 
            commands::remove_employee,
            commands::list_activity, 
            commands::export_activity_csv,
            commands::list_rules, 
            commands::toggle_rule, 
            commands::set_rule_severity, 
            commands::add_rule, 
            commands::delete_rule,
            commands::add_employee,
        ])
        .run(tauri::generate_context!())
        .expect("error running Axiom Admin");
}

// ── Mock Data Helpers ──
fn default_employees() -> Vec<Employee> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    vec![
        Employee { id:"e1".into(), name:"Sarah Chen".into(), email:"s.chen@company.com".into(), department:"Engineering".into(), status:"active".into(), last_seen:now-300_000, total_scans:142, total_detections:38, risk_score:72, avatar_initials:"SC".into() },
        Employee { id:"e2".into(), name:"Marcus Reid".into(), email:"m.reid@company.com".into(), department:"HR".into(), status:"active".into(), last_seen:now-900_000, total_scans:89, total_detections:114, risk_score:91, avatar_initials:"MR".into() },
        Employee { id:"e3".into(), name:"Priya Nair".into(), email:"p.nair@company.com".into(), department:"Finance".into(), status:"active".into(), last_seen:now-120_000, total_scans:201, total_detections:67, risk_score:58, avatar_initials:"PN".into() },
        Employee { id:"e4".into(), name:"James Okafor".into(), email:"j.okafor@company.com".into(), department:"Legal".into(), status:"active".into(), last_seen:now-7_200_000, total_scans:55, total_detections:22, risk_score:40, avatar_initials:"JO".into() },
        Employee { id:"e5".into(), name:"Lena Müller".into(), email:"l.muller@company.com".into(), department:"Sales".into(), status:"inactive".into(), last_seen:now-172_800_000, total_scans:33, total_detections:9, risk_score:28, avatar_initials:"LM".into() },
        Employee { id:"e6".into(), name:"Derek Walsh".into(), email:"d.walsh@company.com".into(), department:"Engineering".into(), status:"suspended".into(), last_seen:now-604_800_000, total_scans:77, total_detections:189, risk_score:97, avatar_initials:"DW".into() },
    ]
}

fn default_activity() -> Vec<ActivityLog> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    vec![
        ActivityLog { id:"a1".into(), employee_id:"e2".into(), employee_name:"Marcus Reid".into(), department:"HR".into(), file_name:"employee_records_Q4.xlsx".into(), detection_count:14, highest_severity:"CRITICAL".into(), timestamp:now-240_000, redacted:true, pii_types:vec!["SSN".into(),"EMAIL".into(),"PHONE".into()] },
        ActivityLog { id:"a2".into(), employee_id:"e3".into(), employee_name:"Priya Nair".into(), department:"Finance".into(), file_name:"payroll_summary.pdf".into(), detection_count:8, highest_severity:"HIGH".into(), timestamp:now-480_000, redacted:false, pii_types:vec!["CREDIT_CARD".into(),"SSN".into()] },
        ActivityLog { id:"a3".into(), employee_id:"e1".into(), employee_name:"Sarah Chen".into(), department:"Engineering".into(), file_name:"onboarding_doc.docx".into(), detection_count:3, highest_severity:"MEDIUM".into(), timestamp:now-720_000, redacted:true, pii_types:vec!["EMAIL".into(),"ADDRESS".into()] },
        ActivityLog { id:"a4".into(), employee_id:"e6".into(), employee_name:"Derek Walsh".into(), department:"Engineering".into(), file_name:"client_data_export.xlsx".into(), detection_count:31, highest_severity:"CRITICAL".into(), timestamp:now-900_000, redacted:false, pii_types:vec!["SSN".into(),"CREDIT_CARD".into(),"DOB".into(),"EMAIL".into(),"PHONE".into()] },
    ]
}

fn default_rules() -> Vec<PolicyRule> {
    vec![
        PolicyRule { id:"r1".into(), name:"Social Security Number".into(), category:"PII".into(), pattern:"\\b\\d{3}-\\d{2}-\\d{4}\\b".into(), severity:"CRITICAL".into(), enabled:true, detection_count:284, description:"Matches US SSN format XXX-XX-XXXX".into() },
        PolicyRule { id:"r2".into(), name:"Credit Card Number".into(), category:"FINANCIAL".into(), pattern:"\\b(?:4[0-9]{12}|5[1-5][0-9]{14})\\b".into(), severity:"CRITICAL".into(), enabled:true, detection_count:117, description:"Matches Visa and Mastercard patterns".into() },
    ]
}