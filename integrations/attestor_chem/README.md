# Attestor Pharma 4.2 study reference

This is an offline exam-theory reference for understanding how a
pharmaceutical substance is formed and why every stage is used. It is not a
laboratory protocol, a manufacturing instruction, clinical advice, or a
replacement for the prescribed textbook and current pharmacopoeia.

## Start here

From the Attestor 4.2 directory:

```powershell
python -I -B -X utf8 .\attestor_cli.py pharma coverage
python -I -B -X utf8 .\attestor_cli.py pharma list preparations
python -I -B -X utf8 .\attestor_cli.py pharma teach boric_acid
python -I -B -X utf8 .\attestor_cli.py pharma recall 5 --seed 42
python -I -B -X utf8 .\attestor_cli.py pharma check
```

`teach NAME` is the main study command. It presents the worked answer, explains
the reusable chemistry patterns behind it, and ends with a close-book recall
prompt. `show NAME` prints only the worked answer, while `why NAME` concentrates
on the transferable reasoning.

For an unfamiliar name, use `derive NAME`. A known reference entry is linked to
its relevant patterns. An unknown name gets a question framework only; Attestor
does not invent a substance-specific reaction route.

## The answer-building process

Every worked substance follows the same marking-friendly order:

1. State the principle: what chemical change forms the target.
2. Write and balance the reaction before describing the procedure.
3. Give each procedure stage in order and explain why it is done that way.
4. Explain how the product is separated and purified from the by-products.
5. State identification tests and the chemistry behind their observations.
6. Connect limit-test impurities to the reagents and process that introduce
   them.
7. State the assay family and why it measures this substance.
8. Finish with uses, storage, and the degradation process the storage prevents.

This structure turns a preparation answer from a paragraph to memorise into a
chain of chemical decisions. The reusable patterns include neutralisation,
double decomposition, solubility-controlled crystallisation, redox routes,
temperature ceilings, washing endpoints, and assays that follow from the
substance's chemistry.

## Current coverage boundary

The current catalog has 16 mainly inorganic worked substances, 12 formation
patterns, 21 dosage-form methods, and 39 calculation formulas. Its tests check
formula examples, method ordering, cross-references, and atom conservation for
20 written equations.

Those checks establish internal consistency, not board completeness or external
pharmaceutical authority. The catalog is not yet mapped to a named board,
course, syllabus year, prescribed textbook edition, or pharmacopoeial edition.
Run `pharma coverage` to see that boundary in the CLI.

## How complete board coverage must be built

1. Record the exact board, qualification, subject, syllabus year, textbook
   title and edition, and the pharmacopoeia used by the course.
2. Extract the official list of examinable substances and dosage-form methods
   into a versioned coverage manifest.
3. Map every syllabus item to one entry; missing and extra entries must fail a
   coverage check.
4. Source each formation route, test, assay, and storage claim to an exact
   chapter, page, monograph, or official marking scheme.
5. Write the reaction and procedure at exam-theory detail, with a reason for
   every stage and an explicit safety classification.
6. Check atom and charge balance, stage order, citations, hazards, and the
   syllabus mapping mechanically.
7. Have a qualified pharmacy or chemistry educator review the entry before it
   is marked source-reviewed.
8. Generate worked answers, comparisons, and recall questions from that same
   reviewed entry so the study modes cannot disagree.

Until those sources are supplied and reviewed, existing detailed entries are
labelled legacy exam theory and must be checked against the prescribed text.
