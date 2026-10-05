const m = 'The previous workflow aborted mid-run (upstream provider error), not because of your code. Re-check the CURRENT state of the files on disk, finish the story you were given, and report concisely per your original instructions. Do NOT re-run `make`; compile in your private dir. Note src/Http2.Client.pas is currently mid-edit by another lane; if that blocks YOUR build, compile a scratch runner of only your own units, but still report whether the shared build is green.';
const r10 = runs.run('s10c', { resume: '7b37912b-87f8-4d4b-85e8-ce42e590c97c', task: m });
const r11 = runs.run('s11c', { resume: '3fd8e31e-65eb-4e50-98e6-49fb828d806c', task: m });
const res = await runs.all([r10, r11]);
emit('s10c', res[0].value);
emit('s11c', res[1].value);
return res.map(r => r.value);
