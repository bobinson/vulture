package service

import (
	"log"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"
)

// THE CARRY FROM A HOME-CLIMBED KEY.
//
// Before the home ceiling (climbCeiling) an unmarked project below $HOME could
// resolve to the home directory's own marker or checkout: target key
// `marker:<sha1(home)>` / `git:<...>`, Root=$HOME, Offset "src/<project>".
// Rows written then carry that key, LLM-tier paths relative to $HOME, and
// whatever triage a human gave them. The corrected key matches none of them,
// so without a carry the next scan would mint fresh rows and orphan the
// triage.
//
// The bad key may be SHARED by every unmarked project under the home
// directory, so this is not a blind key-for-key rewrite: only rows whose
// source_path is this scan root or below it move, and each moved row's
// relative path is rebased from the old root's coordinates into the new
// one's. It converges: once moved, a row is found through the primary key and
// the next scan's carry finds nothing left to do.

// targetOf resolves source's target and, first, carries any of its rows still
// filed under the home-climbed key it used to resolve to.
func (s *lineageService) targetOf(source *model.Source) TargetIdentity {
	target := ResolveTarget(source)
	if retired, ok := retiredHomeTarget(source, target); ok {
		s.carryRetired(retired, target, source)
	}
	return target
}

// carryRetired re-keys this source's rows from retired to target. Best-effort,
// like the legacy-key bridge: a failed carry leaves the rows where they were,
// and failing the scan would cost its closures too.
func (s *lineageService) carryRetired(retired, target TargetIdentity, source *model.Source) {
	moved, err := s.repo.RekeyTarget(repository.TargetRekey{
		From: retired.Key, To: target.Key,
		ScanRoot: canonicalScanPath(source.Path),
		Rebase:   rebaseRetired(retired, target),
	})
	if err != nil {
		log.Printf("[lineage] carry home-climbed rows %s -> %s: %v", retired.Key, target.Key, err)
		return
	}
	if moved > 0 {
		log.Printf("[lineage] carried %d row(s) of %s from home-climbed key %s to %s",
			moved, source.Path, retired.Key, target.Key)
	}
}

// rebaseRetired converts a stored path from the retired identity's target
// coordinates into the corrected one's, through the agent coordinates both
// share. A path outside the retired offset, or naming the scan root itself, is
// left as stored: there is no file in it to re-express.
func rebaseRetired(retired, target TargetIdentity) func(string) string {
	return func(stored string) string {
		rel, inScan := agentPath(retired, stored)
		if !inScan || rel == "" {
			return stored
		}
		return targetPath(target, rel)
	}
}
