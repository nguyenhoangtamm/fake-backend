import { SignJWT, jwtVerify } from 'jose';
import jsonServer from 'json-server';
import auth from 'json-server-auth';
import { TextEncoder } from 'util';

const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(jsonServer.bodyParser);

// Định nghĩa secret key cho JWT
const SECRET_KEY = process.env.SESSION_SECRET || 'e710a357ebbf00ddc0b26c12c2333ee5d590fb53692164d44342c3f87c127257';
const encodedKey = new TextEncoder().encode(SECRET_KEY);

// Tạo JWT
async function encrypt(payload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(encodedKey);
}

// Giải mã JWT
async function decrypt(session = '') {
  try {
    const { payload } = await jwtVerify(session, encodedKey, {
      algorithms: ['HS256'],
    });
    return payload;
  } catch (error) {
    console.log('Failed to verify session');
  }
}

// Tạo phiên làm việc (session)
async function createSession(userId) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const session = await encrypt({ userId, expiresAt });
//   console.log('Session created:', session);
//   // Sử dụng cookie-parser hoặc một thư viện tương tự để thiết lập cookie
//   server.use((req, res, next) => {
//     res.cookie('session', session, {
//       httpOnly: true,
//       secure: true,
//       expires: expiresAt,
//       sameSite: 'lax',
//       path: '/',
//     });
//     next();
//   });
    return session;
}
// RESTful API routes for "todos"
server.use(async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  console.log('Token:', token);
  if (token) {
    const payload = await decrypt(token);
    console.log('Payload:', payload);
    if (payload) {
      req.userId = payload.userId;
      console.log('User ID:', req.userId);
    }

  }
  next();
});

server.get('/todos/user', (req, res) => {
 
  const todos = router.db.get('todos').filter({ userid: req.userId }).value();
  res.status(200).json(todos);
});

server.get('/todos/user/:id', (req, res) => {
 
  const todo = router.db.get('todos').find({ id: parseInt(req.params.id), userid: req.userId }).value();
  if (todo) {
    res.status(200).json(todo);
  } else {
    res.status(404).json({ message: 'Todo not found' });
  }
});

server.post('/todos/user', (req, res) => {
 
  const newTodo = { ...req.body, userid: req.userId };
  router.db.get('todos').push(newTodo).write();
  res.status(201).json(newTodo);
});

server.put('/todos/user/:id', (req, res) => {
 
  const updatedTodo = req.body;
  const todo = router.db.get('todos').find({ id: parseInt(req.params.id), userid: req.userId }).assign(updatedTodo).write();
  if (todo) {
    res.status(200).json(todo);
  } else {
    res.status(404).json({ message: 'Todo not found' });
  }
});

server.delete('/todos/user/:id', (req, res) => {
 
  const todo = router.db.get('todos').remove({ id: parseInt(req.params.id), userid: req.userId }).write();
  if (todo.length > 0) {
    res.status(200).json({ message: 'Todo deleted' });
  } else {
    res.status(404).json({ message: 'Todo not found' });
  }
});




// Middleware để xử lý đăng nhập
server.post('/login', async (req, res) => {
  const email = req.body.email;
    const password = req.body.password;

  const users = router.db.get('users').value();
  const user = users.find(u => u.email === email && u.password === password);

  if (user) {
    const token=await createSession(user.id);
 
    res.status(200).json({ message: 'Login successful', user, token});
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
});

server.use(auth);
server.use(router);

server.listen(8000, () => {
  console.log('JSON Server is running on port 8000');
});