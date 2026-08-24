# Push to GitHub (SSH) — RedOps

Everything is already set on the AWS machine: identity, rewritten history,
and the SSH remote. You only need to move the repo to your laptop and push.

## 1. Create the SSH key on your LOCAL machine (not AWS)

```bash
ssh-keygen -t ed25519 -C "divitichiranjeevi463@gmail.com"
cat ~/.ssh/id_ed25519.pub
```

Add the printed public key to GitHub:
**GitHub → Settings → SSH and GPG keys → New SSH key** (title anything,
key type "Authentication Key").

Verify on your laptop:

```bash
ssh -T git@github.com
# expected: Hi 0xStr1k3r! You've successfully authenticated...
```

## 2. Create the (empty) repo on GitHub first

Go to https://github.com/new and create a repository named **`RedOps`**.
Do NOT tick "Add a README" — the history comes from the transfer.
Keep it private or public as you prefer (public is better for a CV project).

## 3. Move the project from AWS to your laptop

On the **AWS machine**, create the transfer bundle:

```bash
cd /home/ubuntu/redops
git bundle create RedOps.bundle --all
```

Copy it to your laptop (any of these):

```bash
# A. scp (from your laptop)
scp ubuntu@<AWS-IP>:/home/ubuntu/redops/RedOps.bundle ~/

# B. or download via a temporary object-store link
aws s3 cp RedOps.bundle s3://<your-bucket>/RedOps.bundle --acl public-read
```

## 4. Restore on your laptop

```bash
git clone RedOps.bundle RedOps
cd RedOps
git remote remove origin
git remote add origin git@github.com:0xStr1k3r/RedOps.git
```

## 5. Push

Because the history was rebuilt, this is a **first push** to an empty repo:

```bash
git push -u origin main
```

(No force is needed on the very first push to an empty repository.)

## 6. If you ever need to re-push rewritten history

```bash
git push --force-with-lease origin main
```

## After the push: push the release tag

The repo ships with an annotated tag already created (`0.4.6`). Just push it:

```bash
git push origin 0.4.6
```

To tag a later release instead:

```bash
git tag -a 0.5.0 -m "RedOps 0.5.0 — <what changed>"
git push origin 0.5.0
```

Versioning is pre-1.0 semver (no `v` prefix) — `0.x.y` signals the platform is
still evolving; `make build` stamps the tag into `redops version` via
`git describe --tags`.

## Verify the one-liner installs from GitHub

```bash
curl -fsSL https://raw.githubusercontent.com/0xStr1k3r/RedOps/main/install.sh | bash
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied (publickey)` | Key not added to GitHub, or wrong key: `ssh-add -l`, re-add `~/.ssh/id_ed25519.pub` |
| `Permission denied` writing repo | You don't own `0xStr1k3r/RedOps` — check you're logged into the right GitHub account (`ssh -T git@github.com`) |
| `remote: Create a new repository` | Repo doesn't exist yet — create it on GitHub first (step 2) |
| `bundle: Repository contains no commits` | Wrong directory — run from inside the cloned repo |
| `error: failed to push some refs` | Remote isn't empty; see step 6 |