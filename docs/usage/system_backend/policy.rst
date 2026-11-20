Policy
======

.. contents::
   :local:
   :depth: 1

Manipulate policies
-------------------

.. testcode:: sys_policy

    policies = client.sys.list_policies()['data']['policies'] # => ['root']

    policy = """
    path "sys" {
      capabilities = ["deny"]
    }

    path "secret/*" {
      capabilities = ["read", "list"]
    }

    path "secret/foo" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }
    """

    client.sys.create_or_update_policy(
        name='secret-writer',
        policy=policy,
    )

    client.sys.delete_policy('oldthing')

    # The get_policy method offers some additional features and is available in the Client class.
    policy = client.get_policy('mypolicy')

    # Requires pyhcl to automatically parse HCL into a Python dictionary
    policy = client.get_policy('mypolicy', parse=True)

Using Python Variable(s) In Policy Rules
````````````````````````````````````````

.. testcode:: sys_policy

    import hvac

    client = hvac.Client(url='https://127.0.0.1:8200')

    key = 'some-key-string'

    policy_body = """
    path "transit/encrypt/%s" {
        capabilities = ["update"]
    }
    """ % key
    client.sys.create_or_update_policy(
        name='my-policy-name',
        policy=policy_body,
    )


List Policies
-------------

.. automethod:: hvac.api.system_backend.Policy.list_policies
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    list_policies_resp = client.sys.list_policies()['data']['policies']
    print('List of currently configured policies: %s' % ', '.join(list_policies_resp))

Example output:

.. testoutput:: sys_policy

    List of currently configured policies: default, my-policy-name, secret-writer, root


Read Policy
-----------

.. automethod:: hvac.api.system_backend.Policy.read_policy
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    hvac_policy_rules = client.sys.read_policy(name='secret-writer')['data']['rules']
    print('secret-writer policy rules:\n%s' % hvac_policy_rules)

Example output:

.. testoutput:: sys_policy

    secret-writer policy rules:

    path "sys" {
      capabilities = ["deny"]
    }

    path "secret/*" {
      capabilities = ["read", "list"]
    }

    path "secret/foo" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }
    ...

Create Or Update Policy
-----------------------

.. automethod:: hvac.api.system_backend.Policy.create_or_update_policy
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    policy = '''
        path "sys" {
            capabilities = ["deny"]
        }
        path "secret" {
            capabilities = ["create", "read", "update", "delete", "list"]
        }
    '''
    client.sys.create_or_update_policy(
        name='secret-writer',
        policy=policy,
    )

Delete Policy
-------------

.. automethod:: hvac.api.system_backend.Policy.delete_policy
   :noindex:

Examples
````````

.. testcode:: sys_policy

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.sys.delete_policy(
        name='secret-writer',
    )

Batch Policy Changes With Version Evidence
------------------------------------------

Vault policy endpoints are unversioned last-write-wins objects. The batch
interface records the current body of every targeted policy as version
evidence before writing anything, then uses that evidence to skip writes when
another administrator has changed a policy in the meantime and to roll back
only changes whose evidence still matches.

.. automethod:: hvac.api.system_backend.PolicyBatch.apply_policy_batch
   :noindex:

.. automethod:: hvac.api.system_backend.PolicyBatch.rollback_policy_batch
   :noindex:

Examples
````````

Tightening several policies in one guarded batch::

    result = client.sys.apply_policy_batch(
        changes=[
            ("policy-a", 'path "secret/a/*" { capabilities = ["read"] }'),
            ("policy-b", 'path "secret/b/*" { capabilities = ["read", "list"] }'),
        ],
        rollback_on_failure=True,
    )

    print(result.status)              # "succeeded", "failed", or "unknown"
    for entry in result.results:
        print(entry.name, entry.apply_status, entry.rollback_status,
              entry.final_status)

A *known* failure (an HTTP error status Vault documents) restores the policies
the batch applied, but only while their stored body still matches the evidence
captured up front; policies another administrator has since modified are
reported as skipped and left untouched. An *unknown* response stops the batch
without a blind rollback and sets ``readback_required``:

    >>> result.readback_required
    True
    >>> result.readback_names
    ['policy-b']

Read those policies back with :meth:`hvac.api.system_backend.Policy.read_policy`,
and once their real state is known, restore the batch explicitly:

    client.sys.rollback_policy_batch(result)

A runnable, offline walkthrough of creation/replacement, a scripted write
failure, a concurrent administrator update, and an unclassifiable response is
available at ``tests/scripts/policy_batch_demo.py``.
