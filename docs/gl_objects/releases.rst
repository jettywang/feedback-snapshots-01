########
Releases
########

Project releases
================

Reference
---------

* v4 API:

  + :class:`gitlab.v4.objects.ProjectRelease`
  + :class:`gitlab.v4.objects.ProjectReleaseManager`
  + :attr:`gitlab.v4.objects.Project.releases`

* Gitlab API: https://docs.gitlab.com/api/releases/index

Examples
--------

Get a list of releases from a project::

    project = gl.projects.get(project_id, lazy=True)
    release = project.releases.list(get_all=True)

Get a single release::

    release = project.releases.get('v1.2.3')

Edit a release::

    release.name = "Demo Release"
    release.description = "release notes go here"
    release.save()

Create a release for a project tag::

    release = project.releases.create({'name':'Demo Release', 'tag_name':'v1.2.3', 'description':'release notes go here'})

Delete a release::

    # via its tag name from project attributes
    release = project.releases.delete('v1.2.3')

    # delete object directly
    release.delete()

.. note::

    The Releases API is one of the few working with ``CI_JOB_TOKEN``, but the project can't
    be fetched with the token. Thus use `lazy` for the project as in the above example.

    Also be aware that most of the capabilities of the endpoint were not accessible with
    ``CI_JOB_TOKEN`` until Gitlab version 14.5.

Project release links
=====================

Reference
---------

* v4 API:

  + :class:`gitlab.v4.objects.ProjectReleaseLink`
  + :class:`gitlab.v4.objects.ProjectReleaseLinkManager`
  + :attr:`gitlab.v4.objects.ProjectRelease.links`

* Gitlab API: https://docs.gitlab.com/api/releases/links

Examples
--------

Get a list of releases from a project::

    links = release.links.list()

Get a single release link::

    link = release.links.get(1)

Create a release link for a release::

    link = release.links.create({"url": "https://example.com/asset", "name": "asset"})

Delete a release link::

    # via its ID from release attributes
    release.links.delete(1)

    # delete object directly
    link.delete()

Release forensic export
=======================

Reference
---------

* Module:

  + :mod:`gitlab.forensics`
  + :class:`gitlab.forensics.ReleaseForensicCollector`
  + :class:`gitlab.forensics.ForensicVerification`
  + :func:`gitlab.forensics.verify_forensic_export`
  + :func:`gitlab.forensics.summarize_export`

The GitLab UI only shows the *current* release, tag and pipeline state. If a
release tag is force-rebuilt, the asset links shown today can point at a
different build than the one users downloaded at the time of an incident.
``ProjectRelease.forensic_export()`` captures an offline-reviewable evidence
slice that keeps the object versions and the request times exactly as they
were served.

Collect an export for one release::

    release = project.releases.get("v1.2.3")
    evidence = release.forensic_export(output_file="v1.2.3-evidence.json")

The same collection is available through the CLI, without pre-fetching the
release first::

    gitlab project-release forensic-export \
        --project-id 1 --tag-name v1.2.3 --output-file v1.2.3-evidence.json

What the export contains
------------------------

* ``schema``/``schema_version``: format identifier for offline tools.
* ``generated_at``: UTC timestamp of the export.
* ``subject``: project ID, tag name and release ID.
* ``steps``: ordered collection steps (``release``, ``tag:initial``,
  ``release-links``, ``tag:reread``, ``jobs``, ``cross-check``). Each step
  lists its observations, evidence gaps, findings and whether a divergence
  was detected during that step.
* ``observations``: every raw HTTP response, verbatim, with:
  request path/query, request timestamp, status, headers, content type and
  body. The body is stored with its ``sha256`` and byte ``size``.
* ``evidence_gaps``: explicit gap records for permission failures
  (``*_forbidden``), missing objects, interrupted pagination
  (``pagination_aborted``), invalid responses, and safety limits. Every gap
  names the step and, when a response exists, the observation that contains
  its raw body.
* ``cross_checks``: per-asset-link build provenance
  (``asset_links``), the pipelines located from job references
  (``located_pipelines``), findings (``findings``) and a list of
  ``divergences`` with ``detected_at_step``.
* ``integrity``: SHA-256 digest of the canonicalized manifest.

A tag migration during collection is a normal outcome: the tag is read once
before and once after the asset links. Both raw responses are kept, as
``tag:initial`` and ``tag:reread``, and a ``tag_moved`` finding is emitted.

Cross-checking
--------------

Each asset link URL is inspected for a CI job reference (``/-/jobs/<id>``).
For every referenced job the collector resolves the job's pipeline and commit,
then labels the link as:

* ``current`` — the job's commit matches the latest tag snapshot.
* ``historical`` — the job's commit matches an earlier tag snapshot. This is
  how the export can still locate the old pipeline after the tag moved.
* ``unrelated`` — the job's commit matches no captured tag version.
* ``unresolved`` — the job could not be read (see the matching evidence gap).

The resulting finding record includes the observation IDs of the tag, link and
job responses, so a reviewer can jump straight to the raw evidence.

Offline verification
--------------------

.. code-block:: python

    from gitlab import verify_forensic_export

    result = verify_forensic_export("v1.2.3-evidence.json")
    if not result:
        for problem in result.problems:
            print(problem["code"], problem.get("observation_id"))

    from gitlab import summarize_export

    summary = summarize_export(evidence)
    print(summary["cross_checks"]["detected_at_step"])

Verification never contacts GitLab. It re-hashes every stored body and
recomputes the manifest digest over all fields except ``integrity``. This
catches edits to raw bodies, timestamps, gaps and findings alike. It also
rejects dangling references from steps, gaps and findings to observations.

.. note::

   The export intentionally contains no GitLab credentials. It does contain
   raw API responses, which can include private URLs, commit SHAs and user
   metadata; treat the file with the same care as the project audit log.

.. note::

   The manifest digest makes edits detectable, not impossible to forge. For
   adversarial disputes, record ``integrity.manifest_sha256`` in a separate,
   access-controlled system at collection time and compare it when reviewing.
