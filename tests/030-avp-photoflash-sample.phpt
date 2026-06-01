--TEST--
AVP PhotoFlash sample: per-user permit, group permit, and the canonical IsAuthorized example with parents
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
// Mirrors the canonical PhotoFlash sample documented in the AVP
// getting-started tutorial: User / UserGroup / Photo / Album entity
// types under the PhotoFlash namespace, with three policies covering
// per-user view, group-mediated view, and album-scoped updatePhoto.

$store = new Cedar\PolicyStore("PSEXAMPLEabcdefg111111");
$store
    ->loadString("alice-view-vacationphoto", '
        permit (
            principal == PhotoFlash::User::"alice",
            action == PhotoFlash::Action::"view",
            resource == PhotoFlash::Photo::"VacationPhoto94.jpg"
        );
    ')
    ->loadString("alice-friends-view-vacationphoto", '
        permit (
            principal in PhotoFlash::UserGroup::"alice_friends",
            action == PhotoFlash::Action::"view",
            resource == PhotoFlash::Photo::"VacationPhoto94.jpg"
        );
    ')
    ->loadString("alice-updatephoto-in-folder", '
        permit (
            principal == PhotoFlash::User::"alice",
            action == PhotoFlash::Action::"updatePhoto",
            resource in PhotoFlash::Album::"alice_folder"
        );
    ');

$client = new Cedar\AuthorizationClient($store);
$view = [
    "policyStoreId" => "PSEXAMPLEabcdefg111111",
    "action"   => ["actionType" => "PhotoFlash::Action", "actionId" => "view"],
    "resource" => ["entityType" => "PhotoFlash::Photo",  "entityId" => "VacationPhoto94.jpg"],
];

// 1) alice viewing her own photo -> the per-user permit fires
$res = $client->isAuthorized($view + [
    "principal" => ["entityType" => "PhotoFlash::User", "entityId" => "alice"],
]);
echo "1 alice view: ", $res["decision"], " (", count($res["determiningPolicies"]), " policies)", PHP_EOL;

// 2) bob has no matching policy
$res = $client->isAuthorized($view + [
    "principal" => ["entityType" => "PhotoFlash::User", "entityId" => "bob"],
]);
echo "2 bob view:   ", $res["decision"], PHP_EOL;

// 3) carol is a member of alice_friends -> the group permit fires
$res = $client->isAuthorized($view + [
    "principal" => ["entityType" => "PhotoFlash::User", "entityId" => "carol"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "PhotoFlash::User", "entityId" => "carol"],
        "attributes" => [],
        "parents"    => [["entityType" => "PhotoFlash::UserGroup", "entityId" => "alice_friends"]],
    ]]],
]);
echo "3 carol view: ", $res["decision"], PHP_EOL;

// 4) The canonical AVP IsAuthorized request: alice updatePhoto
//    VacationPhoto94.jpg where the photo lives inside alice_folder.
$res = $client->isAuthorized([
    "policyStoreId" => "PSEXAMPLEabcdefg111111",
    "principal" => ["entityType" => "PhotoFlash::User",   "entityId" => "alice"],
    "action"    => ["actionType" => "PhotoFlash::Action", "actionId" => "updatePhoto"],
    "resource"  => ["entityType" => "PhotoFlash::Photo",  "entityId" => "VacationPhoto94.jpg"],
    "entities"  => ["entityList" => [
        [
            "identifier" => ["entityType" => "PhotoFlash::Photo", "entityId" => "VacationPhoto94.jpg"],
            "attributes" => [],
            "parents"    => [["entityType" => "PhotoFlash::Album", "entityId" => "alice_folder"]],
        ],
        [
            "identifier" => ["entityType" => "PhotoFlash::Album", "entityId" => "alice_folder"],
            "attributes" => [],
            "parents"    => [],
        ],
    ]],
]);
echo "4 alice update in folder: ", $res["decision"], PHP_EOL;
echo "  matched: ", $res["determiningPolicies"][0]["policyId"] ?? "(none)", PHP_EOL;

// 5) Same updatePhoto request but for bob -> DENY (no matching policy)
$res = $client->isAuthorized([
    "policyStoreId" => "PSEXAMPLEabcdefg111111",
    "principal" => ["entityType" => "PhotoFlash::User",   "entityId" => "bob"],
    "action"    => ["actionType" => "PhotoFlash::Action", "actionId" => "updatePhoto"],
    "resource"  => ["entityType" => "PhotoFlash::Photo",  "entityId" => "VacationPhoto94.jpg"],
    "entities"  => ["entityList" => [
        [
            "identifier" => ["entityType" => "PhotoFlash::Photo", "entityId" => "VacationPhoto94.jpg"],
            "attributes" => [],
            "parents"    => [["entityType" => "PhotoFlash::Album", "entityId" => "alice_folder"]],
        ],
    ]],
]);
echo "5 bob update in folder: ", $res["decision"], PHP_EOL;
?>
--EXPECT--
1 alice view: ALLOW (1 policies)
2 bob view:   DENY
3 carol view: ALLOW
4 alice update in folder: ALLOW
  matched: alice-updatephoto-in-folder
5 bob update in folder: DENY
