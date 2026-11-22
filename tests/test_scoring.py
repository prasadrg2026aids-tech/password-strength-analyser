import unittest

from analyser import analyze_password
from scoring import score_password


class PasswordScoringTests(unittest.TestCase):
    def test_category_points_sum_to_overall_score(self):
        result = analyze_password("R8!mZ2@pQ6#v")
        self.assertEqual(sum(result.category_scores.values()), result.score)

    def test_common_password_cannot_score_high(self):
        result = analyze_password("Password123!")
        self.assertLessEqual(result.score, 20)
        self.assertEqual(sum(result.category_scores.values()), result.score)

    def test_weighted_score_is_bounded(self):
        score, categories = score_password(
            "Aa1!",
            categories={"uppercase": True, "lowercase": True, "numbers": True, "symbols": True},
            patterns=(),
            is_common=False,
        )
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertEqual(set(categories), {
            "length", "character diversity", "uniqueness", "pattern resistance", "dictionary resistance"
        })


if __name__ == "__main__":
    unittest.main()
