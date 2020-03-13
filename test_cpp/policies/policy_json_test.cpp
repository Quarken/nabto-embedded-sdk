#include <boost/test/unit_test.hpp>

#include <modules/policies/nm_policies_json.h>

#include <platform/np_vector.h>
#include <modules/policies/nm_policy.h>

namespace {

std::string p1 = R"(
{
  "Id": "Policy1",
  "Statements": [
    {
      "Effect": "Allow",
      "Actions": ["GetFoo", "PostBar"]
    },
    {
      "Effect": "Deny",
      "Actions": ["GetSuperSecret"]
    }
  ]
}
)";

} // namespace


BOOST_AUTO_TEST_SUITE(policy_json);

BOOST_AUTO_TEST_CASE(parse1)
{
    struct nm_policy* p;
    cJSON* json = cJSON_Parse(p1.c_str());
    BOOST_TEST(json);
    p = nm_policy_from_json(json);
    BOOST_TEST(strcmp(p->id, "Policy1") == 0);
    BOOST_TEST(np_vector_size(&p->statements) == (size_t)2);
}

BOOST_AUTO_TEST_SUITE_END()
