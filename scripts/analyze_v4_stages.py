import json
from redloop.assessment.orchestrator import TaskOrchestrator
from redloop.assessment.embedding_router import EmbeddingIntentClassifier

with open('tests/fixtures/eval/intent_holdout_v4.json', 'r', encoding='utf-8') as f:
    v4 = json.load(f)

orch = TaskOrchestrator()
clf = EmbeddingIntentClassifier.get_instance()

regex_correct = 0
regex_wrong = 0
regex_stealing_embedding = 0
emb_stage_count = 0
emb_stage_correct = 0
stage_winners = []

for item in v4:
    prompt = item['prompt']
    expected = item['expected_intent']
    
    # What does embedding classifier say on its own?
    emb_pred, emb_conf = clf.classify(prompt)
    
    parsed = orch.parse_intent(prompt)
    final_pred = parsed.get('intent', 'GENERAL_CHAT')
    final_router = parsed.get('router', 'regex')
    
    is_correct = (final_pred == expected)
    
    stage_record = {
        'id': item['id'],
        'expected': expected,
        'final_pred': final_pred,
        'final_router': final_router,
        'correct': is_correct,
        'emb_pred': emb_pred,
        'emb_conf': round(emb_conf, 4)
    }
    stage_winners.append(stage_record)
    
    if final_router == 'embedding_second_stage':
        emb_stage_count += 1
        if is_correct:
            emb_stage_correct += 1
    else:
        if is_correct:
            regex_correct += 1
        else:
            regex_wrong += 1
            if emb_pred == expected:
                regex_stealing_embedding += 1
                print(f"[STOLEN] id={item['id']} exp={expected} regex={final_pred} emb_pred={emb_pred} (conf={emb_conf:.3f}) | {prompt[:65]}...")

print(f"\nTotal: {len(v4)}")
print(f"Final router was embedding: {emb_stage_count} (correct: {emb_stage_correct})")
print(f"Final router was regex/fallback: {regex_correct + regex_wrong} (correct: {regex_correct}, wrong: {regex_wrong})")
print(f"Regex wrong where embedding was right (STOLEN): {regex_stealing_embedding}")

with open('artifacts/v4_stage_winners.json', 'w', encoding='utf-8') as f:
    json.dump(stage_winners, f, indent=2)
print("Saved artifacts/v4_stage_winners.json")
