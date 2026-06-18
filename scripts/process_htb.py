#!/usr/bin/env python3
"""
process_htb.py
Merges HTB API data into a single static/htb/stats.json for the Hugo page.
Run by GitHub Actions after all fetch steps complete.
"""

import json
import os
import sys

DIFFICULTY_WEIGHTS = {
    "Easy": 1,
    "Medium": 2,
    "Hard": 3,
    "Insane": 4,
}

def load(path):
    if not os.path.exists(path):
        print(f"WARNING: {path} not found, skipping")
        return None
    with open(path) as f:
        return json.load(f)

def main():
    profile  = load("static/htb/profile.json")
    activity = load("static/htb/activity.json")
    season   = load("static/htb/season.json")
    matrices = load("static/htb/matrices.json")  # dict of {machine_id: {name, difficulty, aggregate}}

    out = {}

    # --- Profile ---
    if profile:
        p = profile.get("profile", {})
        out["profile"] = {
            "name":          p.get("name"),
            "rank":          p.get("rank"),
            "ranking":       p.get("ranking"),
            "points":        p.get("points"),
            "user_owns":     p.get("user_owns"),
            "system_owns":   p.get("system_owns"),
            "user_bloods":   p.get("user_bloods"),
            "system_bloods": p.get("system_bloods"),
            "respects":      p.get("respects"),
            "avatar":        p.get("avatar"),
            "country_name":  p.get("country_name"),
            "current_rank_progress": p.get("current_rank_progress"),
            "next_rank":     p.get("next_rank"),
        }

    # --- Season ---
    if season:
        d = season.get("data", {})
        out["season"] = {
            "league":             d.get("league"),
            "rank":               d.get("rank"),
            "total_ranks":        d.get("total_ranks"),
            "total_season_points": d.get("total_season_points"),
            "next_rank":          d.get("next_rank", {}).get("title"),
            "flags_obtained":     d.get("total_season_flags", {}).get("obtained"),
            "flags_total":        d.get("total_season_flags", {}).get("total"),
            "flags_to_next":      d.get("flags_to_next_rank", {}).get("obtained"),
            "flags_to_next_total": d.get("flags_to_next_rank", {}).get("total"),
            "user_owns":          d.get("user_owns"),
            "root_owns":          d.get("root_owns"),
        }

    # --- Activity: recent 10, plus OS/difficulty breakdown ---
    if activity:
        items = activity.get("data", [])

        # Deduplicate by machine id for skill/OS/diff calculations (prefer root)
        seen = {}
        for item in items:
            mid = item["id"]
            if mid not in seen or item["type"] == "root":
                seen[mid] = item

        unique_boxes = list(seen.values())

        # Recent activity: pass ALL user+root entries for the 20 most recent unique boxes
        # JS groups them into one row per box showing both badges
        mat = matrices or {}
        recent_ids_ordered = []
        seen_ids = set()
        for item in items:
            if item["id"] not in seen_ids:
                recent_ids_ordered.append(item["id"])
                seen_ids.add(item["id"])
            if len(recent_ids_ordered) >= 20:
                break

        recent_ids_set = set(recent_ids_ordered)
        out["recent"] = [
            {
                "id":         item["id"],
                "name":       item["name"],
                "type":       item["type"],
                "points":     item["points"],
                "ownDate":    item["ownDate"],
                "avatar":     item["avatar"],
                "os":         mat.get(str(item["id"]), {}).get("os", None),
                "difficulty": mat.get(str(item["id"]), {}).get("difficulty", None),
            }
            for item in items
            if item["id"] in recent_ids_set
        ]

    # --- Matrices: skill radar + OS + difficulty ---
    if matrices:
        skill_totals = {"enum": 0, "real": 0, "cve": 0, "custom": 0, "ctf": 0}
        skill_weight_sum = 0
        os_counts = {"Linux": 0, "Windows": 0, "Other": 0}
        diff_counts = {"Easy": 0, "Medium": 0, "Hard": 0, "Insane": 0}

        for mid, data in matrices.items():
            agg = data.get("aggregate")
            if not agg:
                continue

            diff = data.get("difficulty", "Easy")
            weight = DIFFICULTY_WEIGHTS.get(diff, 1)
            os_name = data.get("os", "Other")

            # Weighted skill scores
            for key in skill_totals:
                skill_totals[key] += agg.get(key, 0) * weight
            skill_weight_sum += weight

            # OS breakdown
            if os_name in os_counts:
                os_counts[os_name] += 1
            else:
                os_counts["Other"] += 1

            # Difficulty breakdown
            if diff in diff_counts:
                diff_counts[diff] += 1

        # Normalize skill scores
        if skill_weight_sum > 0:
            skill_radar = {k: round(v / skill_weight_sum, 2) for k, v in skill_totals.items()}
        else:
            skill_radar = skill_totals

        out["skills"] = {
            "radar": skill_radar,
            "os":    os_counts,
            "difficulty": diff_counts,
            "total_boxes": sum(diff_counts.values()),
        }

    # Write output
    os.makedirs("static/htb", exist_ok=True)
    with open("static/htb/stats.json", "w") as f:
        json.dump(out, f, indent=2)

    print("stats.json written successfully")
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
