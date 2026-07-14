Introduction

    "If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat." — Sun Tzu, The Art of War

Your Security Posture Assessment told MedDefense what it has, what protects it and where the gaps are. That is half the picture. The other half: who is on the other side ?

The 2024 Ponemon Institute Healthcare Cybersecurity Report found that 89% of healthcare organizations experienced at least one cyberattack in the previous 12 months. Not because attackers are geniuses. Because healthcare is, structurally, the perfect target. Life-or-death urgency means hospitals will pay ransoms. Legacy medical devices create entry points that do not exist in other industries. Patient data sells for 10 to 40 times more than credit card numbers on underground markets. And most healthcare organizations are chronically understaffed in security.

But "healthcare is targeted" is not actionable intelligence. The question that matters is: who specifically targets organizations like MedDefense, why, how and through which doors ?

A nation-state APT stealing pharmaceutical research operates nothing like a ransomware affiliate buying credentials on a dark web marketplace. A disgruntled billing clerk exfiltrating patient records has a completely different attack profile from an opportunistic teenager scanning for default credentials. Each demands a different defensive response. Treating all threats as equal means defending against none of them effectively.

This project will teach you to think like the adversary, not to become one, but because you cannot build a defense against something you do not understand. You will profile the actors who target hospitals, map the vectors they use, trace the attack paths into MedDefense's specific infrastructure and build threat scenarios that connect directly to the gaps you identified in your posture assessment.
Why It Matters

Threat intelligence is not an academic exercise. It is the difference between spending your security budget on the right things and spending it on the wrong ones. The Threat Landscape Report you produce here will directly shape the vulnerability assessment, the defense strategy and the incident response planning that follow in later projects. Every defensive decision MedDefense makes from this point forward should be informed by the question: "Which threat does this address, and how likely is that threat ?"

Every SOC analyst who investigates an alert needs to know what kind of attacker would produce that pattern. Every incident responder who contains a breach needs to predict the attacker's next move. Every security architect who designs a control needs to know which attack it is designed to stop.

The professionals who get hired are the ones who can answer: "Given what we know about our organization and the threat landscape, where should we focus ?"

After this project, you will be one of them.
Context

Week two at MedDefense Health Systems.

Your Security Posture Assessment landed on the Board's desk last Friday. The reaction was exactly what James Chen hoped for: concern, but not panic. The CEO, Dr. Patricia Morales, called James directly afterward. Her question was pointed: "We now understand our weaknesses. But who are we weak against ? Are we a specific target or just another hospital that could get hit by accident ?"

James walks into your office Monday morning carrying a laptop bag. He sets it on your desk.

"This is Marcus's laptop. IT finally cleared it and gave it back to me. Remember his notes about starting a threat landscape analysis ? The files are on here. CISA advisories, HC3 briefs, some partially annotated ATT&CK mappings. He never finished the work, but the raw material is here."

He opens the laptop and shows you a folder: C:\Users\marcus\Documents\Threat_Intel\

Inside: six files, some annotated, some just downloaded PDFs, a half-written analysis document that stops mid-sentence.

"The Board wants two things. First, they want to know who attacks hospitals like ours and how. Second, they want to know how those threats connect to the specific gaps we identified last week. If the ransomware groups that hit those three regional hospitals use VPN exploits as their primary vector, and we have an unpatched VPN endpoint, that is a very different conversation than a generic 'ransomware is bad' slide."

"Build me a Threat Landscape Report. Make it specific to MedDefense. Make every finding connect back to our posture assessment. And make it something the Board can use to make decisions, not just worry."
Learning Objectives

By the end of this project, you are expected to be able to explain to anyone, without the help of Google:

Threat Actors and Motivations

    The six categories of threat actors and how to distinguish them by behavior, resources and sophistication

    The full range of threat actor motivations and why the same organization can be targeted for different reasons by different actors

    How to profile a threat actor from observed behavior without attribution

    Why ransomware groups target healthcare specifically and how the RaaS model works

    The difference between a malicious insider and a negligent insider, and why both are threats

    How supply chain risk creates exposure that the organization cannot directly control

Threat Vectors and Attack Surfaces

    The complete taxonomy of threat vectors: message-based, file-based, network-based, physical, human and supply chain

    Every major social engineering technique: phishing, vishing, smishing, pretexting, BEC, impersonation, watering hole, brand impersonation, typosquatting

    How to decompose an organization's attack surface into external, internal and human dimensions

    How to trace a vector from initial access through lateral movement to objective

Threat Modeling and Frameworks

    How to apply STRIDE to a specific system architecture to systematically identify threats

    How to map attack steps to MITRE ATT&CK tactics

    How to construct a kill chain showing the full sequence of an attack from entry to impact

    How to correlate an internal gap analysis with an external threat landscape to recalibrate priorities

Professional Communication

    How to produce a Threat Landscape Report that is specific, evidence-based and actionable

    How to communicate threat intelligence to non-technical stakeholders in business terms

Resources

Read or Watch:

Threat Actors and Intelligence

    CISA: Understanding Threat Actors -- Browse the advisory categories to understand the landscape.

    HC3: Health Sector Cybersecurity Coordination Center -- The primary source for healthcare-specific threat intelligence. Read any 2 recent analyst notes.

    ENISA Threat Landscape Report (latest) -- Annual European threat landscape. Read the Executive Summary for methodology.

Attack Vectors and Social Engineering

    NIST SP 800-61 Rev.2: Computer Security Incident Handling Guide -- Chapter 3 covers attack vectors and indicators.

    KnowBe4: Social Engineering Red Flags -- Practical guide to identifying social engineering.

Threat Modeling

    Microsoft: STRIDE Threat Model -- The STRIDE methodology explained with examples.

    MITRE ATT&CK Enterprise Matrix -- The definitive framework. Browse the tactics level first, then explore techniques for Initial Access and Lateral Movement.

Healthcare-Specific Threats

    HHS 405(d): Health Industry Cybersecurity Practices (HICP) -- Read the 5 Current Threats section.

    CISA: Healthcare and Public Health Sector -- Sector-specific guidance and alerts.

Man or Help:

Not applicable for this project. No lab environment is required. All work is performed on provided artifacts, framework references and your deliverables from Project 0x00.
Requirements
General

    All deliverables must be written in professional English.

    A README.md file, at the root of the folder of the project, is mandatory.

    All your files should end with a new line.

Specific Project Rules

    No lab environment is required. This project is artifact-based and analytical.

    Cross-reference your 1x00 deliverables. Your Asset Registry, Criticality Matrix, Gap Analysis and Data Map are inputs to this project. Reference them by name and content. A threat landscape report disconnected from the posture assessment is useless.

    Professional tone is mandatory. Same standard as Project 1x00.

    Specificity over generality. "Ransomware is a threat to hospitals" scores zero."Ransomware groups using VPN exploit chains would target MedDefense's unpatched FortiGate, traverse the flat network to reach ehr-srv-01, and encrypt the EHR database affecting 50,000 patient records" is the standard.

    Cite your reasoning. When you assess likelihood or prioritize a threat, explain what evidence drives that judgment. Sector statistics, MedDefense-specific gaps and threat actor behavior patterns are all valid evidence.
