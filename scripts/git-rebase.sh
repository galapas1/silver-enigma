git checkout main
git fetch origin main
git checkout ${1}
git rebase origin/main
git push origin ${1} --force-with-lease
