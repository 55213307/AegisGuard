# Detection and Response: Evaluation Material for the Final Report

Project: Windows Enterprise Endpoint Security Management System with Machine Learning-based Behavioural Anomaly Detection (AegisGuard).
Covers the work of 6–10 November 2026: the phishing-address model, the malware (PE header) model, the threat-intelligence lists, the command rules, the CVSS-based scoring and lock policy, and their validation on a real virtual machine.

**How to use this file.** Every number below was produced by a run on the project's own code and data (commands in Section 10) or read from a log of the real test machine. Items marked **[verify]** are citations or facts I took from memory or from a web page that was not fully readable, and must be checked before they go into the report. Nothing in this file is estimated.

---

## 1. Summary

1. The system detects five kinds of threat on a Windows endpoint (malicious commands, USB-borne attacks, malicious downloaded files, phishing sources of downloads, password guessing), scores each with CVSS v3.1, and locks the computer and ends the offending processes when the score reaches 7.0.
2. A finding is either **confirmed** (an exact lookup in a public threat list, or a rule for a known attack technique) or a **weak signal** (a machine-learning guess). Only confirmed findings may lock a computer. Weak signals raise a Warning at most. This policy was introduced after a machine-learning guess locked a computer during a Chrome installation (Section 6).
3. Machine-learning accuracy on public datasets depends heavily on how the test is split. The same method scores 96–98% when programs or sites of one family appear on both sides of the split, and 85–93% when the test is made realistic (unseen sites, newer files, a second dataset). Section 4.3 and 4.5 show this with measurements, and it is the main methodological finding of this part of the project.
4. The complete chain (download, hash, blacklist hit, automatic lock, lock screen, ending of running processes, report back, portal record) was demonstrated on a real Windows 11 virtual machine. Ending a running process and its child took 1 second from detection.

| Model | Data | Random split | Realistic split | Used as |
|---|---|---|---|---|
| Phishing address (MLP) | PhiUSIIL + Tranco | not reported | **84.7%** accuracy, AUC 0.828 (split by site) | weak signal |
| Malware by PE header (gradient boosting) | ClaMP (4,560 programs) | **98.4%** | **93.3%** (learn on older, test on newer) | weak signal |
| Malicious command (rules + TF-IDF/LogReg) | LOLBAS, Atomic Red Team, benign (real + synthetic) | 97.2% | 70.7% (unseen attack source); 15.3% false alarms on real commands (was 71.0%), see Section 11 | rules confirm; classifier is weak |

---

## 2. Detection coverage

| Threat | Method | Strength | CVSS (default department) | Action |
|---|---|---|---|---|
| Known-bad file (hash) | exact SHA-256 lookup, MalwareBazaar | confirmed | 7.8 | lock + end processes |
| Unknown malware file (32-bit PE) | gradient boosting on 55 header fields | weak | 7.5 (shown) | Warning only |
| Download from a listed phishing/malware address | exact lookup, OpenPhish + Phishing Army | confirmed | 7.1 | lock + end processes |
| Download from a suspicious address | neural network on the host name | weak | 6.9 (shown) | Warning only |
| Known attack command (LOLBAS technique, PowerShell download-and-run, hidden encoded PowerShell, `bitsadmin /transfer`) | rules | confirmed | 7.8 | lock |
| Command the classifier calls malicious | TF-IDF + logistic regression | weak | 7.5 (shown) | Warning only |
| USB drive: disguised file, autorun, known-bad hash | rules + hash lookup | rules / confirmed | 4.0–7.8 | alert, lock when confirmed |
| BadUSB (keyboard device, then shell within 10 s) | rule on Windows event 6416 + process event | rule | 6.6 | Warning |
| Password guessing | 3 failed logons in 10 minutes | rule | 8.8 | lock |

CVSS values come from `services/cvss.py`: each detection kind has a fixed base vector; the report-confidence metric is *confirmed* or *reasonable*; the environmental metrics change with the employee's department (for example `phishing_url` is 6.9 by default and 8.3 for finance). The lock threshold is 7.0 (`cvss_lock_from`).

**Weak-signal policy.** A weak signal is scored like any finding and its CVSS value stays visible, but its severity is capped at Warning, it is marked `weak_signal` in the event details, and it does not trigger a pop-up alert or the red "alerting" flag on the live-monitoring page.

---

## 3. System flow

Endpoint (Windows scheduled task running as SYSTEM): watches the Downloads folders (every 5 s) and USB drives (every 3 s); for new files it computes the SHA-256, reads the browser's recorded source address (`HostUrl` in the file's Zone.Identifier stream) and, for 32-bit programs, the 55 numbers of the PE header (first bytes of the file only); it uploads this metadata (never the file) to the portal.

Portal backend (FastAPI, PostgreSQL): looks up the hash and the address in the threat-intelligence table, asks the models, scores each finding with CVSS, stores events, locks the computer if a Critical finding exists, and replies with the paths to contain. The agent then ends the processes running from those paths and the processes they started, and reports what it ended. Wazuh (manager on Ubuntu, agent on Windows) supplies the process and logon events for the command and behaviour detections.

---

## 4. Results by component

### 4.1 Threat-intelligence lists (exact lookup)

| List | Content | Entries imported |
|---|---|---|
| OpenPhish community feed | phishing URLs online now | 300 URLs |
| Phishing Army blocklist | phishing domains aggregated from PhishTank, OpenPhish, CERT.PL, urlscan.io and others | 144,114 domains |
| MalwareBazaar (recent) | malware SHA-256 hashes | 993 hashes (556 of 993 have Windows-style file types) |

A hit is a fact with a source, so the finding is confirmed. A miss says nothing. Of the 100,000 most popular domains, 22 appear on the Phishing Army list (mostly link shorteners such as `hubs.ly`, `dub.sh`); none is a large legitimate site, and root domains of free hosting (`web.app`, `github.io`) are not on it. Free feeds refresh every few hours; URLhaus and the MalwareBazaar download endpoints now need an abuse.ch key and were not automated.

### 4.2 Command model

> The numbers in this section are those of 10 November. The model was revised on 11 November: see Section 11.

Design: LOLBAS entries are matched as rules (same program, every switch present); a match is a known technique and counts on its own (confirmed). Three rules of our own were added on 9 November (after the Chrome incident, Section 6) for common attacks that LOLBAS does not spell out as one entry: PowerShell with `IEX` plus `DownloadString`/`DownloadFile`/`Net.WebClient`; PowerShell with a hidden window plus `-enc`; `bitsadmin /transfer` with an http address. Each needs two conditions at once, so that `-EncodedCommand` alone (used by Intune) and `bitsadmin /list` do not match. The classifier (TF-IDF over characters 2–5 and words, then logistic regression, class-balanced) gives a probability; on its own it is a weak signal.

Data: 11,460 commands (7,204 benign, 4,256 malicious); by source: Atomic Red Team 3,119, LOLBAS 1,137, benign 7,044 synthetic + 160 from a real endpoint. 5,776 are distinct once paths and hosts are removed.

| Test | Accuracy | Malicious precision / recall | False-positive rate | AUC |
|---|---|---|---|---|
| 1. Random 80/20 split (2,306 commands), classifier | 98.6% | 0.974 / 0.990 | 1.6% | 0.998 |
| 1. Rules alone | 65.8% | 1.000 / 0.085 | 0.0% | n/a |
| 1. Rules + classifier | 98.6% | 0.974 / 0.990 | 1.6% | 0.998 |
| 2. Unseen source: learn on LOLBAS, test on 3,119 Atomic Red Team commands | **90.3%** | 0.971 / 0.870 | 4.2% | 0.956 |
| 2. Rules alone (unseen source) | 39.5% | 1.000 / 0.023 | 0.0% | n/a |

Interpretation: the rules never raise a false alarm (precision 1.000) but find few attacks; the classifier finds most of them but flags 1.6% of benign commands in the favourable test and 4.2% on a source it has never seen, where accuracy falls by 8 points.

**Known weakness, with its cause.** On real software commands the classifier scores high: Chrome's updater `…\updater.exe --install=appguid=…` 0.93, `GoogleUpdate.exe /ua /installsource scheduler` 0.92, `7z2301.exe` 0.70, `powershell -File backup.ps1` 0.79. Only 160 of the 7,204 benign training commands come from a real endpoint; the rest are synthetic. The classifier therefore learned what synthetic benign commands look like, not what installers look like. This is why a classifier-only verdict cannot lock a computer.

Rule checks on 9 November (all as expected): the 4 attack commands were confirmed by rule (`certutil -urlcache`, `bitsadmin /transfer`, `IEX … DownloadString`, hidden `-enc`); `powershell -NoProfile -EncodedCommand`, `powershell -Command Get-Date`, `bitsadmin /list`, and the Chrome, Google Update and 7-Zip commands were not.

### 4.3 Phishing-address model

**Data.** PhiUSIIL Phishing URL Dataset (Prasad and Chandra, 2024; UCI id 967; CC BY 4.0): 235,795 rows, 100,520 phishing and the rest legitimate after de-duplication. Tranco top-sites list (Le Pochat et al., NDSS 2019): 83,692 legitimate hosts added (bare domains are real; 40% also appear with an everyday subdomain prefix chosen at random by us, which is made up and disclosed).

**Features: the host name only** (21 numbers: length, labels, digits, entropy, longest consonant run, TLD, suspicious words, free-hosting flag, shortener flag, smoothed per-TLD phishing rate learned on the training part). The scheme, a leading `www.` and the path are deliberately ignored.

**Model.** Multi-layer perceptron (64, 32; ReLU; Adam; batches of 512; early stopping on validation loss, best epoch 4), trained one epoch at a time with a Keras-style log. Test is split by registered domain, so no site is on both sides.

| Measure (test set, 58,430 addresses) | Value |
|---|---|
| Accuracy | **84.67%** |
| ROC AUC | 0.8275 |
| Train accuracy | 86.48% |
| Legitimate precision / recall | 0.846 / 0.972 |

| Alert threshold | Phishing caught | Legitimate flagged | Precision |
|---|---|---|---|
| 0.50 | 48.3% | 2.85% | 85.3% |
| 0.70 | 41.7% | 0.81% | 94.7% |
| **0.80 (used)** | 38.8% | 0.40% | 97.0% |
| 0.90 | 34.0% | 0.12% | 98.9% |
| 0.95 | 32.0% | 0.06% | 99.5% |

Legitimate hosts flagged at 0.5, by source: PhiUSIIL 255 of 26,839 (1.0%); Tranco 984 of 16,663 (5.9%). The model is therefore a weak signal tuned for few false alarms rather than high recall.

**Why the first version scored 99.8% and was discarded.** In PhiUSIIL every legitimate address is `https://www.<site>` (a home page), so the scheme, `www.` and the path tell which list an address came from. The first model used them, scored 99.8% and called a real GitHub link phishing. Restricting it to the host removed the shortcut and the accuracy fell to about 85%. A second artefact (legitimate hosts had few subdomains) was reduced by adding Tranco hosts.

**Trusted popular domains.** On 9 November a 7-Zip download (`release-assets.githubusercontent.com`) was flagged 97% phishing: the host-only model dislikes long hyphenated sub-domains even of large sites. The model is now not applied to the 935 domains among the Tranco top 1,000 that are not free-hosting services and have no phishing host in the training data (`google.com` is excluded because `sites.google.com` carries phishing). Measured cost on the test set: phishing alerts 5,790 → 5,717 (−1.3%), legitimate alerts 176 → 175. Choosing the top 10,000 would have lost 224 alerts. The benefit cannot be measured on PhiUSIIL (its legitimate addresses are home pages, not download servers); on 17,000 synthetic download-server hosts built from the 1,000 most popular domains with 17 unseen prefixes, the model alone alerted 7.2% and with the trusted list 1.1%.

**Experiments to raise the accuracy, and what they showed.** The project's target was 96%. Every attempt confirmed that the limit is the data and the way the test is split, not the learner.

| Experiment | Test | Accuracy | Note |
|---|---|---|---|
| Kaggle malicious-URLs set (phishing + malware vs benign), logistic regression on characters 1–4, scheme and `www.` removed | by domain | 91.5% (AUC 0.954) | phishing recall 67.2%, malware 90.0% |
| Same, characters 1–5 + words (500k features) | by domain | 91.3% | |
| Linear SVM, same features | by domain | 89.9% | |
| 47 structural features, gradient boosting | by domain | 88.6% | |
| Stack: out-of-fold text model + 47 features + TLD rate, gradient boosting | by domain | **91.8%** (AUC 0.965) | best of five learners |
| Same models | **random split** | **96.1–96.3%** (AUC 0.988) | same sites on both sides |
| Merged Kaggle + PhiUSIIL + Tranco, stacked | by domain | 87.6% | flagged `download.microsoft.com/…/setup.exe` at 0.9997 |
| Merged without PhiUSIIL | by domain | 90.3% | same address 0.997 |
| Merged, download file names removed | by domain | 89.7% | Microsoft 0.82, `docs.python.org` 0.89 |
| Train on Kaggle, test on PhiUSIIL hosts | cross-dataset | 45%, AUC 0.58 | |
| Pretrained `pirocheto/phishing-url-detection` (MIT, linear SVM; card claims 94.9% accuracy, AUC 0.987) | PhiUSIIL sample 40,000 | 82.6% (AUC 0.932) | 0.0% legitimate flagged, 59.2% phishing caught |
| Same pretrained model | Kaggle, as written (40,000) | 40.6% (AUC 0.600) | 71.3% of legitimate flagged |
| Same | Kaggle with `http://` added | 54.0% | 47.8% of legitimate flagged |
| Same | 20,000 Tranco home pages | 56.8% | 43.2% of legitimate flagged |

The pretrained model's behaviour is explained by one prefix. For the same 10,000 popular domains: `https://www.<domain>` flagged 0.1%; `https://<domain>` 43.6%; `http://<domain>` 33.7%; `https://<domain>/` 52.2%; `https://<domain>/index.html` 94.9% (threshold 0.5). It learned that `www.` means legitimate, the same shortcut as in PhiUSIIL. A CodeBERT model trained on the same Kaggle set (499 MB, no published metrics) was not tested. The conclusion for the report: published accuracy for address classifiers is not comparable unless the split (random or by site) and the source of the legitimate addresses are stated.

### 4.4 Page-content features (prototype, not deployed)

PhiUSIIL also has 28 columns computed from the page (lines of code, forms, password field, links, images, …). On a split by domain, a gradient-boosting model on those columns alone scored **99.75%** (AUC 1.000; 29 legitimate pages flagged and 83 phishing pages missed of 45,023). The most important column was `LineOfCode` (shuffling it costs 19.6 points of accuracy; the median is 1,105 lines for legitimate pages and 12 for phishing pages, many of which are blank or taken-down pages).

A read-only fetcher (`ml/pages.py`: GET only, public addresses only with the IP checked on every redirect, 10 s, 2 MB, no scripts, HTML only; 7 private/loopback/`file://`/`ftp://` addresses refused) computed the 28 features from 18 real legitimate pages. The model flagged 7 of 18 (39%) as phishing: pages that are small, minified, built by JavaScript, or that returned 403 to the fetcher (`news.ycombinator.com`, `info.cern.ch`, `lite.cnn.com`, `archive.org`, `httpbin.org/forms/post`, `paypal.com/signin`, `stackoverflow.com`). The 99.75% therefore does not transfer to real pages, and the prototype was not connected to the scan.

### 4.5 Malware model on PE headers

**Data.** ClaMP, file `ClaMP_Raw-5184.csv` (Kumar et al. **[verify citation]**; Kaggle `saurabhshahane/classification-of-malwares`): 5,184 Windows programs with 55 header numbers each. 624 exact duplicates were removed (a copy on both sides of a split would measure memory), leaving **4,560** (2,072 malware, 2,488 benign). 5,172 of the 5,184 are 32-bit, so the model is only asked about 32-bit programs.

**Models.** Gradient boosting (scikit-learn `HistGradientBoostingClassifier`, 5 trees per epoch, early stopping on validation loss, best epoch 39 = 195 trees) and, for comparison, a neural network (64, 32). The saved model is refitted on all 4,560 programs with the same number of trees.

| Test | Model | Accuracy | AUC | Malware caught | Benign flagged |
|---|---|---|---|---|---|
| Random 80/20 split | gradient boosting | **98.4%** | 0.9994 | 98.1% | 1.4% |
| Random 80/20 split | neural network | 96.4% | 0.9937 | 96.4% | 3.6% |
| Learn on programs compiled up to 2011 (3,126), test on 1,434 compiled later | gradient boosting | **93.3%** | 0.9901 | 95.8% | 7.4% |
| Same time split | neural network | 75.7% | 0.9463 | 95.8% | 29.7% |

The neural network matches the trees on a random split but collapses on newer programs, so the trees were chosen. Train accuracy is 1.000 against 0.933 on the newer programs, which shows how much of the random-split score is memory of families.

| Alert threshold (time split) | Malware caught | Benign flagged | Precision |
|---|---|---|---|
| 0.50 | 95.8% | 7.36% | 78.0% |
| 0.90 | 91.2% | 1.69% | 93.6% |
| 0.95 | 90.6% | 1.15% | 95.5% |
| **0.99 (used)** | 81.1% | 0.27% | 98.8% |

Most important header fields on the newer programs: `MajorImageVersion`, `Characteristics`, `Subsystem`, `CheckSum`. Without `Subsystem`, `CheckSum` and `Characteristics` the random-split accuracy is 97.4%, so the score does not rest on one field.

**Cautions that must be stated.** (a) The malware share changes by compile year (about 10% in 2006, 78% in 2011, 19% in 2012), so the year is partly a proxy for where the benign files were collected. (b) Most programs are from 2005–2012; a fixed percentile cut left only 57 test programs in a first attempt, so the cut is chosen to leave at least 25%. (c) The benign programs are older Windows files.

**Header reader on the endpoint.** The PowerShell function `Get-PeHeader` reads only the first bytes of a file. It was compared field by field with the `pefile` library on 222 real 32-bit programs of the development PC: **all 55 fields identical for all 222**; none of the 178 other files (64-bit or not PE) was wrongly accepted, and no 32-bit program was missed.

**Real programs.** 0 of those 222 real programs (184 Windows system files, 38 from Program Files (x86)) were flagged at 0.99 or even at 0.5; the highest score was 0.152. They are signed, mainstream programs, so this is a weak test of false alarms on small or unusual software.

### 4.6 USB and BadUSB rules

A USB drive's file list is checked for a double extension, a hidden program, a shortcut standing in for a hidden folder, and an `autorun.inf` that starts an unsigned program, and every program's hash is looked up (the scan agent runs as a SYSTEM task and also reports back what it ended). BadUSB is a rule: a keyboard device appearing (event 6416) followed within 10 seconds by a command interpreter. It scores 6.6 (Medium) and does not lock; with its vector's scope set to *changed* it would be 7.6, but the vector was not tuned to force a result.

---

## 5. Validation on a real machine

Setting: Windows 11 Enterprise (10.0.26200) virtual machine as the endpoint; Ubuntu virtual machine with the portal, PostgreSQL and Wazuh 4.14.8 manager; scan agent installed by the generated one-click installer.

| Time (10 Nov) | Action | Observed |
|---|---|---|
| 11:55:43 | Download of the 7-Zip 32-bit installer | `0 finding(s), 0 locked, 0 to contain`; HTTP 200; no alert |
| 12:05:12 | The installer's hash was put on the blacklist as `demo-test`; the file was copied to Downloads under a new name | `1 finding(s), 1 locked, 1 to contain`; automatic lock; Critical CVSS 7.8 `malware-like download` shown in the portal; the computer's screen was covered and keyboard and mouse were blocked |
| 12:29:23 | A copy of `cmd.exe` was run from Downloads with a child `ping -t 127.0.0.1`; its hash was blacklisted as `demo-test` | locked at 12:29:23; `Containment … 2 ended, 0 failed` at 12:29:24 (the program and its child); after unlock neither process existed |
| later | Security Logs | the record `Containment on Downloads: 2 process(es) ended (PING.EXE, run-test.exe)` is listed |

These tests used harmless files and temporary blacklist entries (removed afterwards); no real malware was downloaded or run. They show that the chain works, not what the detection rate is on real malware.

---

## 6. Defects found by testing, and their fixes

| # | Defect | Evidence | Fix |
|---|---|---|---|
| 1 | A download scan with no findings returned HTTP 500 and the agent retried for ever (an empty list was inserted as a row of defaults) | web-server log: three `POST /api/agent/scan 500` about 10 s apart, then 200 after the fix | skip the insert when there are no rows |
| 2 | A classifier-only verdict locked the computer during a Chrome installation (CVSS 7.5, "72% chance this command is malicious") | portal event at 06:01 PM on 9 November | classifier-only verdicts are weak (Warning, no lock); precise rules added for real attacks |
| 3 | The scan agent's script filled the Windows environment block (32,358 of 32,767 characters) after the PE reader was added | computed from the generated installer | the script is gzip-compressed before it is put in the environment (14,864 characters); round trip checked byte for byte |
| 4 | The address model flagged a 7-Zip download from `release-assets.githubusercontent.com` at 97% | portal event at 06:14 PM on 9 November | popular-domain exemption (Section 4.3) |
| 5 | After the Ubuntu VM was rebooted the Wazuh manager failed to start (`wazuh-apid … Killed`; no out-of-memory record found; cause not established) | `systemctl is-active` = failed | a systemd drop-in restarts it on failure after 30 s |
| 6 | After the installer was run again the Windows agent enrolled itself as a new Wazuh agent instead of using the key the portal had issued, so the portal showed Offline | `client.keys` held a new agent named after the computer; the manager listed it besides the pre-registered one | re-running a freshly downloaded installer restored the correct agent; root cause not proven |

The pattern in 1–4: a model or a rule was tested on its own, and the problem only showed when it met real traffic. Real-machine tests with ordinary software (an installer, a browser update) found what dataset tests did not.

---

## 7. Limitations and threats to validity

- **Datasets are not the target traffic.** PhiUSIIL legitimate addresses are home pages; the Kaggle set mixes sources; ClaMP's benign programs are older Windows files. Realistic splits lower every score (Sections 4.3, 4.5), and the numbers here are not detection rates for the threats a company will meet.
- **Made-up data.** 40% of the Tranco hosts carry a subdomain prefix chosen by us; most benign commands are synthetic.
- **64-bit programs are not judged** by the PE model (the data has 11 of 5,184), although most current programs are 64-bit.
- **Address model uses the host only**; the same host can serve good and bad files. It cannot judge the content.
- **Trusted-domain list** trades 1.3% of phishing alerts for fewer false alarms on large vendors; its benefit was shown on synthetic hosts and one real case.
- **Command classifier** still scores real installer commands high; it is kept from locking, not fixed.
- **Blacklists only know what has been reported.** New files and addresses depend on the models, which are weak signals.
- **Tests used harmless files.** The lock and the ending of processes were shown with files whose hashes were blacklisted by us, not with malware.
- **Single endpoint and a small scale.** One Windows 11 virtual machine, one portal; no measurement of load or of many endpoints.
- **Operational:** the Wazuh start failure after a reboot and the duplicate-agent enrolment were mitigated but their root causes were not found.

## 8. Future work

Train the PE model on a dataset that includes 64-bit programs; add real installer and updater commands to the benign set of the command classifier; evaluate the address model on addresses taken from real download logs; repeat the real-machine test with a controlled, contained malware sample in an isolated environment; automate the abuse.ch feeds with a key; find the cause of the Wazuh start failure.

---

## 9. Datasets and sources

| Resource | Use | Licence / terms |
|---|---|---|
| PhiUSIIL Phishing URL Dataset, Prasad and Chandra, Computers & Security, 2024; UCI id 967 | address model | CC BY 4.0 |
| Tranco list, Le Pochat et al., NDSS 2019, tranco-list.eu | legitimate hosts, popular-domain list | research list |
| Malicious URLs dataset (Kaggle, `sid321axn/malicious-urls-dataset`) | comparison experiments only | check the page **[verify]** |
| ClaMP (Kaggle, `saurabhshahane/classification-of-malwares`) | PE model | check the page **[verify]** |
| LOLBAS project; Atomic Red Team | command rules and classifier | open-source projects (check licences) **[verify]** |
| OpenPhish community feed; Phishing Army; MalwareBazaar (abuse.ch) | threat-intelligence lists | each site's terms of use |
| `pirocheto/phishing-url-detection` (Hugging Face) | tested, not used | MIT |
| Hannousse and Yahiouche, "Towards benchmark datasets for machine learning based website phishing detection", arXiv:2010.12847 | source of the pretrained model's data (reported on the card's link) | |
| CVSS v3.1 specification (FIRST) | scoring | |

## 10. Reproduction and artefacts

Run from `company/backend` with the project's virtual environment.

```
python -m app.services.ml.urls          # address model: log, report, 8 charts, saves ml_models/url_model.joblib
python -m app.services.ml.files         # PE model: both tests, summary table, 8 charts, saves ml_models/file_model.joblib
python -m app.services.ml.commands      # command model: tests 1 and 2, 7 charts (overwrites ml_models/command_model.joblib)
python -m app.services.threat_intel fetch                  # OpenPhish + Phishing Army
python -m app.services.threat_intel stats
python -m app.services.ml.urls_full --quick                # the larger address experiment (not deployed)
```

Charts (training curves, confusion matrix, ROC, precision-recall, score distribution, feature importance, decision boundary on a 2-D projection, which is for illustration only): `backend/ml_reports/urls/`, `backend/ml_reports/files/`, `backend/ml_reports/commands/`, and the experiment's own `ml_reports/urls_full/`.

Code: `app/services/ml/{urls,urls_full,files,pages,commands,runtime}.py`, `app/services/{cvss,threat_intel,scan_results,usb_scan}.py`, the scan agent in `app/services/installer.py` (`Get-PeHeader`, `Get-SourceUrl`, `Stop-FromLocation`).

---

## 11. Addendum, 11 November: command model revised (supersedes the numbers of Section 4.2 and the command row of Section 1)

A review of the whole system found two defects in the command detection, both invisible in the earlier tests because those used commands typed by hand, not commands as the agent delivers them.

**Defect A: escaped command lines.** Wazuh delivers a command line as it stands in its JSON: every backslash doubled and every quote preceded by a backslash. Read that way, the program of a quoted path was not recognised, so no LOLBAS rule matched a quoted attack command (for example a quoted full path to certutil with -urlcache), and no path was normalised as a path. Commands written that way throughout are now put back before they are judged; a UNC path is left alone. Checked on 10 cases (4 attacks confirmed by rule in escaped and plain form, 6 benign not confirmed).

**Defect B: the classifier had never seen a real system command.** Only commands a person ran were used as real benign data (160); what Windows, its services and software updaters run was left out. Measured on the real command lines of the two captures, the old model called 66-73% of them malicious.

**Change.** The benign set now also holds every different command line of the first test computer that a person did not run (583, source `endpoint-system`) and the 204 of a second capture (`capture-2`). Two real commands that a rule recognises as an attack technique were left out of the benign set (the test computers are where attacks were tried by hand). Dataset: 12,245 commands (Atomic Red Team 3,119; LOLBAS 1,137; synthetic benign 7,043; real: 159 + 583 + 204).

| Test | Before | After |
|---|---|---|
| 1. Random 80/20 split: accuracy / false-positive rate / AUC | 98.6% / 1.6% / 0.998 | 97.2% / 2.8% / 0.997 |
| 1. Malicious precision / recall | 0.974 / 0.990 | 0.957 / 0.972 |
| 2. Unseen source (learn on LOLBAS, test on Atomic Red Team): accuracy | 90.3% | 70.7% |
| 2. Malicious precision / recall | 0.971 / 0.870 | 0.927 / 0.525 |
| 2. AUC | 0.956 | 0.948 |
| 3. Real commands of a capture not learned from (176 commands), called malicious at 0.5 | 71.0% | 15.3% |
| 3. Same, at 0.8 | 69.9% | 6.2% |

**Reading.** Test 3 is the one that matters in use: false alarms on real commands fell from 71% to 15%. Test 2 fell from 90% to 71% because recall on the unseen attack source dropped from 87% to 53% while the AUC stayed almost the same (0.956 to 0.948). The earlier recall was inflated: a classifier that calls 71% of real benign commands malicious also "catches" most attacks, because it had learned to separate synthetic benign commands from everything that looks real. The revised model ranks commands about as well and is honest about the threshold. Test 1 is slightly lower because the test set now contains real commands, which are harder than synthetic ones (false alarms in test 1: 9.4% of the first computer's system commands, 25.7% of the second capture's, 1.5% of the synthetic ones).

**What this means for the design.** The classifier remains a weak signal (Warning, never a lock). The confirmed path is the rules, whose precision is 1.000 in every test. Remaining weakness: installers started from a Downloads folder still score around 0.5 (a Chrome updater 0.53, a 7-Zip installer 0.51) and `powershell -File` 0.87.

**Other fixes of 11 November.** (1) When one file had both a model's guess and a list hit, the higher CVSS score was reported; a weak 7.5 could hide a confirmed 7.1 and keep the computer from being locked. A confirmed or rule finding now always comes first. (2) The three saved supervised models (`ml_models/command_model.joblib`, `url_model.joblib`, `file_model.joblib`) are loaded when the service starts and the log names each one; they are trained offline only, never by the running service (the 7-day retraining applies to the unsupervised behaviour model alone).

New chart: `ml_reports/commands/8_real_commands_false_alarms.png`. All 24 charts of the three supervised models were regenerated on 11 November.

## 12. Addendum, 11 November (later): command model, labels cleaned and tests widened (supersedes the "After" column of Section 11)

**Why test 2 was low.** A test of Atomic Red Team is a script. The first version labelled every line of it malicious, including lines that only change folder, print a message, wait, create a working folder or open and close a block (cd, echo, mkdir, Write-Host, if ... {). 591 of 3,119 lines were such scaffolding. They are now left out (`commands.is_scaffolding`, judged by how the line starts only), which leaves 2,528 Atomic Red Team lines and a dataset of 11,654 commands.

**Model.** Same features (TF-IDF over characters 2-5 and words, logistic regression). The regularisation was changed from C=10 to C=3. Variants tried and not adopted, each judged on three checks at once (cross-source both ways, real commands): C=1, C=30, characters 1-4, words only, and 21 hand-written indicator features of what a command does (alone: AUC 0.65 on test 2; added to TF-IDF: fewer false alarms on real commands but lower recall on the unseen source). None moved the ranking quality (AUC about 0.90-0.95 on test 2) by more than noise: the limit of test 2 is that the model has only seen one kind of attack, not the learner.

| Test (classifier alone) | Accuracy | Attacks caught | Benign flagged | AUC |
|---|---|---|---|---|
| 1. Random 80/20 split, near-copies kept on one side | 96.1% | 97.3% | 4.6% | 0.994 |
| 2. Learn LOLBAS only, test on Atomic Red Team | 77.3% | 58.9% | 3.1% | 0.952 |
| 2b. Learn Atomic Red Team only, test on LOLBAS | 91.7% | 83.8% | 4.6% | 0.964 |
| 4. Unseen ATT&CK techniques (117 techniques, 5 folds; each technique with all its commands from both sources is tested without one example of it in the learning part) | 91.1% | 94.2% | 10.4% | 0.980 |
| 3. Real commands of a capture not learned from, called malicious | 18.2% (71.0% without real system commands in the learning part) | | | |

**Reading.** Tests 2 and 2b are stress tests: the model learns the attacks of one project only. LOLBAS is narrow (abuse of signed Windows programs), so learning from it alone finds 59% of the broader Atomic Red Team attacks, while the other direction finds 84%. Test 4 is closer to use, where the model has learned from both projects and meets a technique it has no example of: 91.1%, with 94% of the attacks caught. Its false-alarm rate (10.4%) is the reason the classifier stays a weak signal.
