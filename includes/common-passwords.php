<?php
defined( 'ABSPATH' ) || exit;

/**
 * Kleine Liste besonders häufig verwendeter (und damit unsicherer) Passwörter.
 * Wird unabhängig von den übrigen Kriterien immer geprüft, wenn "forbid_common"
 * aktiv ist. Keine vollständige Leak-Datenbank, sondern ein schneller,
 * offline funktionierender Basisschutz gegen die absoluten Klassiker.
 */
function fgr_pp_common_passwords(): array {
    return [
        '123456', '123456789', '12345678', '12345', '1234567', '1234567890',
        'password', 'passwort', 'password1', 'passwort1', 'qwertz', 'qwerty',
        'qwertz123', 'qwerty123', 'abc123', 'abcd1234', 'letmein', 'welcome',
        'willkommen', 'monkey', 'dragon', 'master', 'login', 'admin', 'admin123',
        'administrator', 'root', 'toor', 'iloveyou', 'sunshine', 'princess',
        'football', 'baseball', 'starwars', 'trustno1', 'superman', 'batman',
        '111111', '000000', '123123', '1q2w3e4r', 'changeme', 'test1234',
        'wordpress', 'wordpress1', 'passw0rd', 'p@ssw0rd', 'p@ssword', 'hallo123',
        'hallo1234', 'berlin123', 'sommer2024', 'sommer2025', 'winter2024',
        'winter2025', 'muster123', 'geheim', 'geheim123', 'schalke04',
        'passwort123', 'ficken', 'hunter2', 'zaq1zaq1', 'asdfasdf', 'asdf1234',
        '1qaz2wsx', 'qazwsx', 'qwe123', 'freedom', 'whatever', 'access',
        'shadow', 'michael', 'jennifer', 'jordan23', 'computer', 'internet',
    ];
}
