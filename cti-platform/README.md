# منصة استخبارات التهديدات الأمنية (CTI Security Intelligence Platform)

منصة مستقلة لاستخراج وربط وإثراء مؤشرات التهديد من تقارير CTI النصية (عربي/إنجليزي)،
مع نموذج NER قابل للتدريب، وربط MITRE ATT&CK، وتصدير STIX 2.1، ورسم بياني معرفي،
وواجهة REST API مع لوحة مراقبة عربية RTL داكنة بأسلوب CAD.

> المشروع منعزل تماماً ولا يمس أي ملف خارج مجلد `cti-platform`.

---

## المكونات

| الوحدة | الدور |
| --- | --- |
| `app/ner/` | نواة بالحقول العشوائية الشرطية **CRF** (sklearn-crfsuite/lbfgs + Viterbi) + قواميس intel + عبارات MITRE |
| `app/eval/` | مصفوفة ارتباك رمزية، مقاييس نطاقات، تقييم خط الإنتاج الكامل |
| `app/enrichment/` | VirusTotal / AbuseIPDB / AlienVault OTX + قاعدة Offline دائماً |
| `app/mitre/` | فهرس تقنيات ATT&CK وربط الوسوم |
| `app/graph/` | مولّد رسم Knowledge Graph (حواف co-occur/exploits/maps_to) |
| `app/stix/` | مولّد حزمة STIX 2.1 (indicators, malware, threat-actor, attack-pattern) |
| `web/` | لوحة مراقبة عربية (قياس + استخراج + رسم بياني + MITRE + سمعة) |

## التشغيل

```powershell
# 1) بيئة افتراضية (Python 3.11)
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt

# 2) مفاتيح الإثراء (اختياري — عند غيابها تعمل القاعدة غير المتصلة)
$env:CTI_VT_KEY="..."
$env:CTI_ABUSEIPDB_KEY="..."
$env:CTI_OTX_KEY="..."

# 3) تشغيل المنصة
.\.venv\Scripts\python run.py
```

ثم افتح `http://localhost:8010`.

**أو مباشرة عبر uvicorn:**
```powershell
.\.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8010
```

## البيانات والنموذج

- **التدريب**: 304 سجلًّا مولّدًا (`synth.generate_corpus(seed=7)`) منها **270 جملة معنونة**
  بإجمالي **573 رمزًا معنونًا** — تشمل قوالب مفردة وقوالب **مختلطة متعددة الكيانات**
  (`MIXED_TEMPLATES`) لرفع كثافة التعلم. التوزيع: URL 178، GROUP 74، EMAIL 72، TECHNIQUE 70،
  MALWARE 50، VULN 33، DOMAIN/IP/CVE 24 لكلٍّ، HASH 24.
- **الاختبار** (142 سجلًّا): مجموعة يدوية حقيقية `CORPUS` منفصلة غير مرئية أثناء التدريب.
- الترميز `BIO`؛ الرموز تُبني من **النص النظيف** (بعد إزالة أقواس التسميات) عبر نفس المحوّل
  اللغوي المستخدم في الاستدلال لضمان تطابق تدفق الرموز تماماً (`_clean_with_value_spans`).
- **الخوارزمية:** Conditional Random Fields (CRF) عبر `sklearn-crfsuite` (تحسين `lbfgs`) بسمات
  سياقية (±2 كلمة، شكل، بادئات/لواحق، قواميس) بدل المصنّف العدّادي القديم.

### أداء النموذج CRF وحده (على المجموعة اليدوية)

| المقياس | Precision | Recall | F1 |
| --- | --- | --- | --- |
| **Token Macro** | 0.8976 | 0.8583 | **0.8682** |
| **Span (كيان كامل)** | 0.875 | 0.744 | **0.8042** |

أبرز الأنواع (Span F1): VULN/URL/EMAIL/HASH/CVE = 1.0، DOMAIN 0.94، IP 0.91، GROUP 0.90،
MALWARE 0.81، TECHNIQUE 0.65 (FILE_NAME بنمط واحد فقط في الاختبار).

### خط الإنتاج (regex + CRF + قواميس + عبارات MITRE)

نطاقات الكشف على مجموعة التقييم اليدوية — المطابقة التامة على مستوى الكيان:

| المستوى | Precision | Recall | F1 |
| --- | --- | --- | --- |
| **الكل** | 0.9767 | 0.9882 | **0.9825** |
| TECHNIQUE | 1.0 | 1.0 | 1.0 |
| MALWARE | 1.0 | 0.9762 | 0.9880 |
| GROUP | 0.9167 | 0.9565 | 0.9362 |
| IP | 0.8182 | 1.0 | 0.9 |
| CVE / DOMAIN / EMAIL / HASH / URL / VULN / FILE_NAME | 1.0 | 1.0 | 1.0 |

بعد توسعة مجموعة التدريب (270 جملة معنونة بدل 80، وقوالب مختلطة) قفز النموذج CRF وحده من
**token F1 = 0.74 و span F1 = 0.58** إلى **0.87 و 0.80**؛ regex + عبارات MITRE + قواميس
ترفع النتيجة النهائية للمنتج إلى F1 ≈ 0.982 (خطأان مفقودان و4 إيجابيات كاذبة من 170 كياناً،
مع TECHNIQUE/URL/VULN/CVE/EMAIL/DOMAIN/HASH مثالية).
مسار الترقية المقترح: ضبط دقيق على SecBERT/CyNER مع `transformers`.

## نقاط الواجهة

| المسار | الوصف |
| --- | --- |
| `GET /health` | حالة الخدمة والنموذج |
| `GET /api/eval` | مقاييس الرموز/النطاقات/خط الإنتاج + مصفوفة الارتباك |
| `POST /api/extract` | `{text, enrich}` ⇒ كيانات + ملخص + رسم + STIX |
| `POST /api/analyze/file` | ملف PDF/TXT/Log (multipart) |
| `GET /api/mitre/techniques?q=injection` | فهرس تقنيات ATT&CK مع بحث |
| `POST /api/enrichment/reputation` | `{type, value}` ⇒ سمعة مجمّعة |
| `GET /api/sample` | نص تجريبي جاهز |
| `/` | لوحة المراقبة العربية |

## الاختبارات

```powershell
.\.venv\Scripts\python -m pytest tests -q
```

37 اختباراً تغطي البيانات، المستخرج، المقاييس، STIX/الرسم، ونقاط REST.

## الشكل الهيكلي

```
cti-platform/
├─ run.py  app/  web/  tests/  requirements.txt  README.md
└─ data/            # قاعدة Offline Intelligence (تُنشأ عند أول إثراء)
```