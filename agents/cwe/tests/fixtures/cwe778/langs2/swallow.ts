const a = () => {
  api.get().then(setX).catch(() => {});
  api.get().catch(() => setSubmittable(false));
  api.get().catch(() => '');
  api.get().catch(next);
  api.get().catch(err => {
    console.error(err);
  });
  api.get().catch(err => {
    setError(err.message);
  });
};
