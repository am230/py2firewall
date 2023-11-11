Profile Link Tree Generator
===========================

.. image:: https://img.shields.io/github/license/mashape/apistatus.svg
    :target: http://opensource.org/licenses/MIT
.. image:: https://badge.fury.io/py/py2firewall.svg
    :target: https://badge.fury.io/py/py2firewall

Installation
------------

.. code:: bash

    pip install py2firewall

Usage
-----

.. code:: python
    
    from py2firewall.firewall import get_firewall
    from py2firewall.rule import Action, Direction, RuleBuilder


    rule = RuleBuilder("When Twitter is X")
    rule.add_remote_domain("twitter.com")\
        .set_action(Action.BLOCK)\
        .set_direction(Direction.OUTBOUND)
    firewall = get_firewall()
    firewall.add_rule(rule.build())