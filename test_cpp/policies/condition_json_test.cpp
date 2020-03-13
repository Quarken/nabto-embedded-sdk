#include <boost/test/unit_test.hpp>

#include <modules/policies/nm_policies_json.h>
#include <modules/policies/nm_condition.h>

#include <cjson/cJSON.h>

namespace {

std::string c1 = R"(
{ "StringEquals" : { "var1": ["val1", "val2", "val3"] } }
)";

std::string c2 = R"(
{ "Bool" : { "var1": ["true", "false"] } }
)";

std::string i1 = R"(
{ "InvalidOperator": { "Invalid", ["42"] } }
)";

std::string i2 = R"(
{ "StringEquals": { "Invalid", [42] } }
)";

std::string i3 = R"(
{ "StringEquals": "bar" }
)";

} // namespace

BOOST_AUTO_TEST_SUITE(policies_json)

BOOST_AUTO_TEST_CASE(parse_c1)
{
    struct nm_condition* c;
    cJSON* json = cJSON_Parse(c1.c_str());
    BOOST_TEST(json != (cJSON*)NULL);
    c = nm_condition_from_json(json);
    BOOST_TEST(c);
    BOOST_TEST(c->op == NM_CONDITION_OPERATOR_STRING_EQUALS);
    BOOST_TEST(strcmp(c->key, "var1") == 0);
    BOOST_TEST(np_string_set_contains(&c->values, "val1"));
    BOOST_TEST(np_string_set_contains(&c->values, "val2"));
    BOOST_TEST(np_string_set_contains(&c->values, "val3"));
}

BOOST_AUTO_TEST_CASE(parse_c2)
{
    struct nm_condition* c;
    cJSON* json = cJSON_Parse(c2.c_str());
    BOOST_TEST(json);
    c = nm_condition_from_json(json);
    BOOST_TEST(c);
    BOOST_TEST(c->op == NM_CONDITION_OPERATOR_BOOL);
    BOOST_TEST(strcmp(c->key, "var1") == 0);
    BOOST_TEST(np_string_set_contains(&c->values, "true"));
}

BOOST_AUTO_TEST_SUITE_END()
