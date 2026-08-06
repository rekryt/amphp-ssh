<?php

declare(strict_types=1);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PSR1' => true,
        '@PSR2' => true,
        // The project puts the opening brace on the same line for classes and
        // functions. This deliberately overrides PSR-2 and must stay that way.
        'braces_position' => [
            'classes_opening_brace' => 'same_line',
            'functions_opening_brace' => 'same_line',
            'allow_single_line_anonymous_functions' => true,
            'allow_single_line_empty_anonymous_classes' => true,
        ],
        'array_syntax' => ['syntax' => 'short'],
        'cast_spaces' => true,
        'combine_consecutive_unsets' => true,
        'declare_strict_types' => true,
        'function_to_constant' => true,
        // cs-fixer 3 defaults this to `@compiler_optimized`, which STRIPS the
        // leading `\` from every other native call. The codebase qualifies all
        // native functions (\pack, \strlen, \substr); `@internal` keeps that.
        'native_function_invocation' => [
            'include' => ['@internal'],
            'scope' => 'all',
            'strict' => true,
        ],
        'multiline_whitespace_before_semicolons' => true,
        'no_unused_imports' => true,
        'no_useless_else' => true,
        'no_useless_return' => true,
        'no_whitespace_before_comma_in_array' => true,
        'no_whitespace_in_blank_line' => true,
        'non_printable_character' => true,
        'normalize_index_brace' => true,
        'ordered_imports' => true,
        'php_unit_construct' => true,
        'php_unit_dedicate_assert' => true,
        'php_unit_fqcn_annotation' => true,
        'phpdoc_summary' => true,
        'phpdoc_types' => true,
        'psr_autoloading' => true,
        'return_type_declaration' => ['space_before' => 'none'],
        'short_scalar_cast' => true,
        'blank_lines_before_namespace' => true,
    ])
    ->setFinder(
        PhpCsFixer\Finder::create()
            ->in(__DIR__ . '/examples')
            ->in(__DIR__ . '/src')
            ->in(__DIR__ . '/tests')
    )
;
