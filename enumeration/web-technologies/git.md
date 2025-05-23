# Git

{% code overflow="wrap" fullWidth="true" %}
```bash
https://eagain.net/articles/git-for-computer-scientists/

# ALWAYS CHECK 
HEAD 
refs/head/main
git show $COMMIT
git config -l

# ENUMERATE BRANCHES
git branch
git branch -r
# CHANGE BRANCHES
git checkout branch2

git status
git log --name-only --oneline
# In case we want to download a commit file and then reverting back to the last commit
git checkout $COMMIT -- $COMMIT_FILE
git reset --hard $LAST_COMMIT

# Basic information
git show #show commits or files
git show <branch-name>
git show <commit-id>
git show <tag-name>
git --git-dir /path/to/.git show

# Configuration
git config --list

# Commit history
git log #Show all logs about commits and so on
git log -p
git log --stat
git --git-dir /path/to/.git log --stat

# Compare the two commits
git diff
git diff --staged
git diff --cached

# Working tree status
git status
git ls-tree #list the contents of a tree folder
find . -name HEAD | xargs strings #find more info about HEAD which is a reference to commit objects in master
# Tags
git tag -n    # list all tags
git show $tag # show a specific tag
# Push files
git add $FILE # add a file to the local repository
git commit -m "text to identify commit" # add file to HEAD index
git push -u origin master # push changes to remote repository (master branch)
```
{% endcode %}

## Github, .git secrets

| [https://www.puckiestyle.nl/source-code-disclosure-via-exposed-git-folder/](https://www.puckiestyle.nl/source-code-disclosure-via-exposed-git-folder/) |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [https://github.com/internetwache/GitTools](https://github.com/internetwache/GitTools)                                                                 |

GitGuardian Trufflehog Shhgit gitLeaks Gitrob

### GitTools

<pre class="language-bash" data-overflow="wrap" data-full-width="true"><code class="lang-bash">Use https://github.com/arthaud/git-dumper, more up to date
NOTE: Always check Docker files and remember their info
<strong>
</strong><strong># Dumper can be used to download an exposed .git directory from a website 
</strong>./gitdumper.sh http://10.10.58.41/.git/ clone #clone will be used as dumper folder, use ls -la to see .git inside
# Alternative
wget -r $IP.../.git

# Extract .git repo
./extractor.sh REPO_DIR DESTINATION_DIR
./extractor.sh clone repo #if .git is inside clone folder, repo is the folder to be extracted
# Take a local .git directory and recreate the repository in a readable format.
./extractor.sh REPO_DIR DESTINATION_DIR
# Finder can be used to search the internet for sites with exposed .git directories. 

Gittools --> search inside .git/logs/HEAD for extra info

# After getting commits, check commit-meta.txt and the parent field to sort the commits. The one with no parent will be the oldest one (first commit).
</code></pre>

## Search for commits

```bash
# - go to .git/logs/ folder and locate HEAD file
# - cat HEAD file and discard the repetitive words from most of commits
strings HEAD | grep -v 'init repo' | grep -v 'moving from'
# Once we have found our commit, show it
git show 06fbefc1da56b8d552cfa299987097ba1213da12

#------------------ANOTHER WAY
#We went into the heads directory of the git logs .git/logs/refs/heads/
ls -lna | sort -n -r #to see if there are some abnormally smaller or bigger
```

## Hooks (privesc)

{% code overflow="wrap" fullWidth="true" %}
```sh
https://git-scm.com/docs/githooks
man githooks

pre-commit for git commit??
post-merge for git pull and some others

# Pre-commit hooks
https://verdantfox.com/blog/view/how-to-use-git-pre-commit-hooks-the-hard-way-and-the-easy-way
https://gtfobins.github.io/gtfobins/git/
https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks
```
{% endcode %}

## git status (privesc)

[https://www.sonarsource.com/blog/securing-developer-tools-git-integrations/#root-cause-git-local-configuration](https://www.sonarsource.com/blog/securing-developer-tools-git-integrations/#root-cause-git-local-configuration)

## Gitlab&#x20;

{% code overflow="wrap" fullWidth="true" %}
```sh
# Authenticated
Look for projects and see if we can edit them, make merge requests to master branch and so on in order to inject code on the webserver.

# Default creds
https://gitlab.com/gitlab-org/gitlab-foss/-/commit/8a01a1222875b190d32769f7a6e7a74720079d2a
```
{% endcode %}

Look for projects and see if we can edit them, make merge requests to master branch and so on in order to inject code on the webserver.

## References

{% embed url="https://medium.com/@talgoldfus/better-understanding-gits-work-flow-in-order-to-properly-deal-with-merge-conflicts-part-i-760a366fc997#:~:text=Whats%20the%20difference%20between%20push,refs%20along%20with%20associated%20objects%E2%80%9D." %}

{% embed url="https://git-scm.com/book/en/v2/Git-Basics-Viewing-the-Commit-History" %}

{% embed url="https://dzone.com/articles/top-20-git-commands-with-examples" %}
