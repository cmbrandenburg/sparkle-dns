# Sparkle-DNS Release Checklist

1. Resolve any `FIXME` comments in the code.

2. Ensure the `sparkle` crate builds and runs using the latest
   dependencies.

        $ cargo update &&
          cargo test &&
          cargo test --release

  If any errors occur then fix them.

3. Ensure packaging succeeds.

        $ cargo package

  If any errors occur then fix them.

4. Create a temporary Git branch for the release.

        $ git checkout -b release_prep

5. Update project files.

    1. Edit `Cargo.toml` to declare the correct version for this
       crate.

        1. E.g., remove any version suffix (e.g., `-master`).

        2. Ensure the documentation link is correct.

    2. Edit `CHANGELOG.md` to add the date for the new release and
       remove the “unreleased” adjective. Ensure the change log is
       up-to-date, clear, and well formatted.

    3. Edit `README.md` to update all references to the latest release
       and next release.

    4. Ensure there are no untracked files in the working directory.

    5. Commit changes.

            $ git commit

6. Merge updates into master.

        $ git checkout master &&
          git merge release_prep &&
          git branch -d release_prep

7. Publish the crate.

        $ cargo publish

8. Create Git tag.

        $ ver=$(grep '^version\s=' Cargo.toml | head -n1 | sed -Ee 's/.*"([0-9]+\.[0-9]+\.[0-9]+)"$/\1/') &&
          test 1 == $(echo "$ver" | wc -w) &&
          git tag -a v$ver -m "v$ver release" &&
          git push --tags

9. Prep for new work.

    1. Edit `Cargo.toml` to increment the version, adding the `-master`
       suffix.

    2. Edit `CHANGELOG.md` to add the new “unreleased” section for the
       next version.

    3. Commit changes

            $ git commit -m "Prep for work on the next release"

    4. [Close the issue milestone for the new release](
       https://github.com/cmbrandenburg/sparkle-dns/milestones).
