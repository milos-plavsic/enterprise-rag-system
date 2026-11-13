# Evaluation scope and plan

The checked-in fixtures/evaluation.json and eval_benchmark.py are authored
synthetic functional regression cases. Success on these cases does not estimate
real-world semantic relevance, production RAG accuracy or business value.
Confidence labels in the original demo were uncalibrated and are removed.

## Run the offline comparison

Generate the synthetic corpus with `python synthetic_data.py`. Then use
`python eval_retrieval.py --ranking lexical --k 4` for the baseline. For dense
and hybrid comparisons, install the optional ML dependencies, set
`RAG_EMBEDDING_MODEL` to an approved model, and repeat with `--ranking dense`
and `--ranking hybrid`. Keep the data, questions, and cutoff fixed.
`--data-dir` and `--fixture` allow a separately labelled corpus and test set.

The dense cosine floor is 0.40 by default. The comparison records the active
floor. Use `RAG_DENSE_MIN_SCORE` for model-specific experiments, and choose
it with separate development and held-out data. The default is a conservative
demo operating point, not a calibrated probability or a universal threshold.

The ranking unit is a distinct source, not a chunk. The best-ranked chunk
represents its source and duplicate sources are removed before applying k.
Precision@k divides by k, counting empty slots as misses. Recall@k divides
by the number of labelled relevant sources. MRR and nDCG use the same source
positions. Abstentions and permission leaks are reported separately. Timings
include retrieval, not model loading, API transit, or generation.

The API-to-model transport test uses a loopback stub and verifies that only
authorised evidence is sent. It does not measure model answer quality. No
independently labelled representative corpus, provider credentials, or
enterprise IdP is bundled. Do not report this regression suite as evidence
that a real neural model improves retrieval or that citations entail answers.

For a production evaluation:

1. Define use cases, cost of errors, permission classes and accepted abstention.
2. Sample realistic, authorised queries from each role and source type.
3. Obtain independent expert labels for expected evidence and answer correctness.
4. Freeze evaluation guidelines and separate development from held-out sets.
5. Compare BM25, dense and hybrid retrieval on Recall@k, MRR, nDCG and latency.
6. Evaluate citation entailment, numerical correctness, complete answers and
   unsupported claims, independently of retrieval ranking.
7. Include denied, unanswerable, contradictory, stale and injection-bearing cases.
8. Treat permission leaks as blocking failures rather than average-score effects.
9. Report subgroup metrics, uncertainty, tail latency, operational cost and
   error categories. Track regressions when sources or models change.
10. Conduct blinded human evaluation and quantify cost per successful task
    and net time saved versus the client's current workflow.

A deployable release requires independent security review, real-data validation,
an approved privacy/data contract, load testing and a documented go/no-go decision.
These external gates are NOT yet met.
