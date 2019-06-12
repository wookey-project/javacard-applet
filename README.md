# Wookey Javacard applets

[![Release](https://img.shields.io/github/release/wookey-project/javacard-applet.svg)](https://github.com/wookey-project/javacard-applet/releases/latest)
[![Travis CI Build Status](https://api.travis-ci.com/wookey-project/javacard-applet.svg?branch=master)](https://travis-ci.com/wookey-project/javacard-applet)

## About Wookey applets

The WooKey project authentication, DFU and signature tokens are implemented using JavaCard (https://docs.oracle.com/en/java/javacard/).

JavaCard is a public ecosystem for developing and distributing code on secure elements. Actually, this is one of the only frameworks allowing to access secure elements without signing NDAs: this makes it a perfect match for open source projects since the source code can be distributed.

JavaCard systems (composed of a secure IC and a JavaCard framework) are usually certified using the EAL Common Criteria scheme: this ensures that security and penetration tests as well as code review have been performed by entitled ITSEF (Information Technology Security Evaluation Facility) using a formal and approved process.

This makes certified JavaCards an interesting choice for hardened components when designing security solutions: they are robust against a wide variety of advanced attack scenarios.

For the WooKey project, we have validated our JavaCard applets on an EAL 4+ NXP JCOP J3D081 (https://www.fi.muni.cz/~xsvenda/jcalgtest/run_time/NXPJCOPJ3D081.html). This JavaCard is dual interface (contact and contacless), is JavaCard 3.0.1 and GlobalPlatform 2.2 compliant, and is EAL 4+ certified. The public certification report can be found here:

https://www.commoncriteriaportal.org/files/epfiles/0860b_pdf.pdf

The JCOP J3D081 have been chosen for price and availability reasons. Please note that the WooKey project applets should be compatible with any JavaCard 3.0.1 and above compatible card!


## About compilation step


The JavaCard and GlobalPlatform ecosystems require tools for compiling as well as pushing the compiled applets (CAP files) to the target. Fortunately, open source components are available for all these steps.

Compiling can be performed using the ant-javacard project, with Oracle SDKs:

https://github.com/martinpaljak/ant-javacard

https://github.com/martinpaljak/oracle_javacard_sdks

Pushing the compiled applets can be done through the GlobalPlatformPro tool:

https://github.com/martinpaljak/GlobalPlatformPro
