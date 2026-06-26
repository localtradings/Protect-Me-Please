import express from 'express';

const app = express();

app.use(express.json());

app.post('/api/admin/users', async (req, res) => {
  const role = req.body.role;
  const isAdmin = req.body.isAdmin;

  res.json({ role, isAdmin });
});

app.listen(3000);
