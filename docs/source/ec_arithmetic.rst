=========================
Elliptic Curve arithmetic
=========================

The python-ecdsa also provides generic API for performing operations on
elliptic curve points.

.. warning::

    This is documentation of a very low-level API, if you want to
    handle keys or signatures you should look at documentation of
    the :py:mod:`~ecdsa.keys` module.

Short Weierstrass curves
========================

There are two low-level implementations for
:term:`short Weierstrass curves <short Weierstrass curve>`:
:py:class:`~ecdsa.ellipticcurve.Point` and
:py:class:`~ecdsa.ellipticcurve.PointJacobi`.

Both of them use the curves specified using the
:py:class:`~ecdsa.ellipticcurve.CurveFp` object.

You can either provide your own curve parameters or use one of the predefined
curves.
For example, to define a curve :math:`y^2 = x^3 + 1 * x + 4 \text{ mod } 5` use
code like this:

.. code:: python

    from ecdsa.ellipticcurve import CurveFp
    custom_curve = CurveFp(5, 1, 4)

The predefined curves are specified in the :py:mod:`~ecdsa.ecdsa` module,
but it's much easier to use the helper functions (and proper names)
from the :py:mod:`~ecdsa.curves` module.

For example, to get the curve parameters for the NIST P-256 curve use this
code:

.. code:: python

    from ecdsa.curves import NIST256p
    curve = NIST256p.curve

.. tip::

    You can also use :py:class:`~ecdsa.curves.Curve` to get the curve
    parameters from a PEM or DER file. You can also use
    :py:func:`~ecdsa.curves.curve_by_name` to get a curve by specifying its
    name.
    Or use the
    :py:func:`~ecdsa.curves.find_curve` to get a curve by specifying its
    ASN.1 object identifier (OID).

Affine coordinates
------------------

After taking hold of curve parameters you can create a point on the
curve. The :py:class:`~ecdsa.ellipticcurve.Point` uses affine coordinates,
i.e. the :math:`x` and :math:`y` from the curve equation directly.

To specify a point (1, 1) on the ``custom_curve`` you can use this code:

.. code:: python

    from ecdsa.ellipticcurve import Point
    point_a = Point(custom_curve, 1, 1)

Then it's possible to either perform scalar multiplication:

.. code:: python

    point_b = point_a * 3

Or specify other points and perform addition:

.. code:: python

    point_b = Point(custom_curve, 3, 2)
    point_c = point_a + point_b

To get the affine coordinates of the point, call the ``x()`` and ``y()``
methods of the object:

.. code:: python

    print("x: {0}, y: {1}".format(point_c.x(), point_c.y()))

Projective coordinates
----------------------

When using the Jacobi coordinates, the point is defined by 3 integers,
which are related to the :math:`x` and :math:`y` in the following way:

.. math::

   x = X/Z^2 \\
   y = Y/Z^3

That means that if you have point in affine coordinates, it's possible
to convert them to Jacobi by simply assuming :math:`Z = 1`.

So the same points can be specified as so:

.. code:: python

    from ecdsa.ellipticcurve import PointJacobi
    point_a = PointJacobi(custom_curve, 1, 1, 1)
    point_b = PointJacobi(custom_curve, 3, 2, 1)


.. note::

    Unlike the :py:class:`~ecdsa.ellipticcurve.Point`, the
    :py:class:`~ecdsa.ellipticcurve.PointJacobi` does **not** check if the
    coordinates specify a valid point on the curve as that operation is
    computationally expensive for Jacobi coordinates.
    If you want to verify if they specify a valid
    point, you need to convert the point to affine coordinates and use the
    :py:meth:`~ecdsa.ellipticcurve.CurveFp.contains_point` method.

Then all the operations work exactly the same as with regular
:py:class:`~ecdsa.ellipticcurve.Point` implementation.
While it's not possible to get the internal :math:`X`, :math:`Y`, and :math:`Z`
coordinates, it's possible to get the affine projection just like with
the regular implementation:

.. code:: python

    point_c = point_a + point_b
    print("x: {0}, y: {1}".format(point_c.x(), point_c.y()))

All the other operations, like scalar multiplication or point addition work
on projective points the same as with affine representation, but they
are much more effective computationally.

Multi-scalar multiplication of public points
=============================================

When a verification routine needs a linear combination of several public
points, :math:`s_0 P_0 + s_1 P_1 + \ldots + s_k P_k`, the
:py:mod:`~ecdsa.multi_mul` module provides a single bounded entry point,
:py:func:`~ecdsa.multi_mul.multi_scalar_mul`.

The interface is deliberately restricted so that one oversized request
cannot exhaust a worker process:

* only the five NIST prime curves and ``secp256k1`` are accepted, matched
  against the named curves in :py:mod:`~ecdsa.curves` (an ad-hoc curve that
  merely compares equal is rejected);
* at most :py:data:`~ecdsa.multi_mul.MAX_TERMS` (16) point/scalar terms per
  request;
* the precomputation table never exceeds
  :py:data:`~ecdsa.multi_mul.MAX_TABLE_ENTRIES` (512) point entries and the
  window never exceeds :py:data:`~ecdsa.multi_mul.MAX_WINDOW` (8);
* every point is checked against the curve equation, points from different
  curves are rejected, and all of these checks run **before** any table
  entry is allocated.

Zero, negative and order-boundary scalars are accepted; scalars are reduced
modulo the curve order, so repeated points and mutually cancelling terms
evaluate correctly (including to the point at infinity). The caller's point
objects are never modified: the implementation works on private copies.

.. code:: python

    from ecdsa.curves import NIST256p
    from ecdsa.multi_mul import multi_scalar_mul

    generator = NIST256p.generator
    points = [generator * 2, generator * 3, generator * 5]
    scalars = [7, 11, 13]
    result = multi_scalar_mul(points, scalars)
    assert result == generator * (2 * 7 + 3 * 11 + 5 * 13)

Pass ``return_stats=True`` to additionally receive the selected window, the
allocated table size and the number of point additions and doublings
performed.

For one or two terms the existing
:py:meth:`~ecdsa.ellipticcurve.PointJacobi.mul_add` is at least as fast and
allocates no table, so :py:func:`~ecdsa.multi_mul.public_point_combination`
routes such small requests there automatically (the threshold is
:py:data:`~ecdsa.multi_mul.MUL_ADD_TERMS_THRESHOLD`, three terms).

.. warning::

    This interface is intended for **public verification material only**.
    It is a size-bounded, input-validating front end; it is **not**
    constant time and is not a side-channel resistant implementation. Do
    not use it with private keys or secret scalars.

The ECDSA verifier exposes the same public point combination through
:py:meth:`~ecdsa.ecdsa.Public_key.verifies_via_multi_scalar`. It verifies
one signature at a time; it is not a batch verification scheme and does not
merge the verification equations of distinct signatures.
