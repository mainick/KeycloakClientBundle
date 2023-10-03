<?php

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__)
    ->exclude(['var', 'vendor', 'config/secrets', 'public', 'node_modules', 'tests/Fixtures']);

return (new PhpCsFixer\Config())
    ->setRules([
        '@Symfony' => true,
        // 'strict_param' => true,
        // 'declare_strict_types' => true,
        'no_leading_import_slash' => true,
        'no_trailing_comma_in_singleline' => true,
        'no_whitespace_in_blank_line' => true,
        'no_trailing_whitespace' => true,
        'no_space_around_double_colon' => true,
        'multiline_whitespace_before_semicolons' => true,
        'blank_lines_before_namespace' => true,
        'single_blank_line_at_eof' => true,
        'control_structure_continuation_position' => ['position' => 'next_line'],
    ])
    ->setFinder($finder);
