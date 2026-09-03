use clap::Parser;
use kcc::cli::{Args, Commands, InspectionType};

/// 从解析结果中取出 Check 子命令的命名空间
fn check_namespace(args: &Args) -> Option<String> {
    match &args.command {
        Commands::Check { namespace, .. } => namespace.clone(),
        _ => panic!("expected Check command"),
    }
}

#[test]
fn test_cli_parsing() {
    // Default check
    let args = Args::try_parse_from(&["kcc", "check"]).unwrap();
    assert!(matches!(&args.command, Commands::Check { .. }));

    // With namespace
    let args = Args::try_parse_from(&["kcc", "check", "-n", "kube-system"]).unwrap();
    assert_eq!(check_namespace(&args).as_deref(), Some("kube-system"));

    // With custom output
    let args = Args::try_parse_from(&["kcc", "check", "-o", "custom-report.md"]).unwrap();
    let Commands::Check { output, .. } = &args.command else {
        panic!("expected Check command");
    };
    assert_eq!(output.as_deref(), Some("custom-report.md"));

    // With format
    let args = Args::try_parse_from(&["kcc", "check", "-f", "json"]).unwrap();
    assert!(matches!(&args.command, Commands::Check { .. }));
}

#[test]
fn test_cli_lang_parsing() {
    use kcc::reporting::Lang;

    let lang_of = |args: &Args| -> Lang {
        match &args.command {
            Commands::Check { lang, .. } => *lang,
            _ => panic!("expected Check command"),
        }
    };

    // Default language is Chinese.
    let args = Args::try_parse_from(&["kcc", "check"]).unwrap();
    assert_eq!(lang_of(&args), Lang::Zh);

    // --lang en switches to English.
    let args = Args::try_parse_from(&["kcc", "check", "--lang", "en"]).unwrap();
    assert_eq!(lang_of(&args), Lang::En);

    // --language is a visible alias for --lang.
    let args = Args::try_parse_from(&["kcc", "check", "--language", "zh"]).unwrap();
    assert_eq!(lang_of(&args), Lang::Zh);
}

#[test]
fn test_inspection_type_variants() {
    use clap::ValueEnum;

    let types = InspectionType::value_variants();
    assert!(types.len() >= 6); // 至少有 6 种巡检类型

    // 校验各类型可被解析
    assert!(matches!(
        "all".parse::<InspectionType>(),
        Ok(InspectionType::All)
    ));
    assert!(matches!(
        "nodes".parse::<InspectionType>(),
        Ok(InspectionType::Nodes)
    ));
    assert!(matches!(
        "pods".parse::<InspectionType>(),
        Ok(InspectionType::Pods)
    ));
    assert!(matches!(
        "security".parse::<InspectionType>(),
        Ok(InspectionType::Security)
    ));
}

#[test]
fn test_server_subcommand() {
    let args = Args::try_parse_from(&["kcc", "server", "--addr", "0.0.0.0:5005"]).unwrap();
    match &args.command {
        Commands::Server { addr, .. } => assert_eq!(addr, "0.0.0.0:5005"),
        _ => panic!("expected Server command"),
    }
}

#[test]
fn test_node_inspector_subcommand() {
    let args = Args::try_parse_from(&["kcc", "node-inspector"]).unwrap();
    assert!(matches!(&args.command, Commands::NodeInspector { .. }));
}
