import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { decode, sign, verify } from 'hono/jwt'

const app = new Hono();
app.use("/*", cors());

app.get('/', async (c) => {
  return c.text( "Hello World!" );
});
app.get('/profile/:id', async c => {
  let result = await c.env.DB.prepare(`SELECT * FROM Profiles where id = ?`).bind(c.req.param('id')).first();
  if ( !result ) {
    c.status(404);
    return c.json({ message: "No user found" });
  }
  let responseObj = JSON.parse( result.data );
  responseObj.id = result.id;
  return c.json( responseObj );
});
app.get('/map/:code', async c => {
  let result = await c.env.DB.prepare(`SELECT p.data FROM Profiles p inner join Mappings m on m.profile = p.id where m.code = ?`).bind(c.req.param('code')).first();
  if ( !result ) {
    c.status(404);
    return c.json({ message: "No user found" });
  }
  result = JSON.parse( result.data );
  result.code = c.req.param('code');
  return c.json( result );
});

const authSecret = 'ShareByC2LauthSecretKey';
const auth = new Hono();
auth.post( "/login", async c => {
  const creds = await c.req.json();
  creds.encodedPassword = btoa( creds.password );
  const result = await c.env.DB.prepare( `SELECT * FROM users where email = ? and password = ?` )
  .bind( creds.email, creds.encodedPassword ).first();
  if( result ) {
    console.log( result );
    let payload = {
      id: result.id,
      email: creds.email,
      iat: Date.now()/1000,
      nbf: Date.now()/1000,
      exp: (Date.now()/1000) + (7*24*60*60)
    };
    payload = await sign( payload, authSecret );
    return c.json({
      message: "Signin successful",
      jwt: payload
    });
  } else {
    c.status( 404 );
    return c.json({
      message: "No user found"
    });
  }
});
auth.post( "/register", async c => {
  const creds = await c.req.json();
  creds.encodedPassword = btoa( creds.password );
  try {
    const code = (Math.random()*999999+"").slice( 0, 6 );
    const result = await c.env.DB.prepare( `INSERT INTO users(email, password, verification_code) values(?, ?, ?)` )
    .bind( creds.email, creds.encodedPassword, code ).run();

    if( result ) {
      let payload = {
        email: creds.email,
        iat: Date.now()/1000,
        nbf: Date.now()/1000,
        exp: (Date.now()/1000) + (7*24*60*60)
      };
      payload = await sign( payload, authSecret );
      return c.json({
        message: "Registration successful",
        jwt: payload
      });
    }
  } catch(e) {
    console.log( e );
    c.status( 401 );
    return c.json({
      message: "Email already registered",
      error: e.toString()
    })
  }
});

const api = new Hono();
api.use('/*', async (c, next) => {
	const authToken = c.req.header("Authorization");
	if( authToken ) {
    try {
      const token = authToken.split("Bearer ");
      c.set("user", await verify(token[1], authSecret));
      await next();      
    } catch (error) {
      console.log( error );
      c.status("401");
      return c.json({message: "User not authorised"});
    }
  } else {
		c.status("401");
		return c.json({message: "User not authorised"});
	}
});

api.get('/profile', async c => {
  const payload = c.get('user');
  let {results} = await c.env.DB.prepare(`SELECT p.id, p.data from profiles p INNER JOIN users u on u.id = p.user where u.email = ? `)
  .bind(payload.email).all();
  if ( results.length ) {
    results = results.map( r =>{
      let d = JSON.parse( r.data );
      d.id = r.id;
      return d;
    });
    return c.json( results );
  } else {
    c.status( 404 );
    return c.json({ message: "Not found" });
  }
});
api.get('/profile/:id', async c => {
  let result = await c.env.DB.prepare(`SELECT * FROM Profiles where id = ?`).bind(c.req.param('id')).first();
  let responseObj = JSON.parse( result.data );
  responseObj.id = result.id;
  return c.json( responseObj );
});
api.post('/profile', async c => {
  let profileObj = await c.req.json();
  console.log( profileObj );
  const payload = c.get('user');
  const user = await c.env.DB.prepare(`SELECT * FROM Users where email =?`).bind( payload.email ).first();
  if ( user ) {
    const result = await c.env.DB.prepare(`INSERT INTO profiles(name, data, user) values(?, ?, ?)`).bind( profileObj.info.name, JSON.stringify( profileObj ), user.id ).run();
    console.log( `Creating: ${result}` );
    profileObj.id = result.meta.last_row_id;
    return c.json( profileObj );
  } else {
    c.status( 401 );
    return c.json({message: "Not authorised"});
  }
});

api.put('/profile/:id', async c => {
  let profileObj = await c.req.json();
  console.log( profileObj );
  const payload = c.get('user');
  const user = await c.env.DB.prepare(`SELECT * FROM Users where email =?`).bind( payload.email ).first();
  if ( user && c.req.param('id') ) {
    const result = await c.env.DB.prepare(`UPDATE profiles SET name = ?, data = ? where user = ? and id = ?`).bind( profileObj.info.name, JSON.stringify( profileObj ), user.id, profileObj.id ).run();
    console.log( `Updating: ${result}` );
    return c.json( profileObj );
  } else if ( user && !c.req.param('id') ) {
    c.status( 403 );
    return c.json({
      message: "Profile ID required"
    });
  } else {
    c.status( 401 );
    return c.json({message: "Not authorised"});
  }
});
api.delete('/profile/:id', async c => {
  const payload = c.get('user');
  const user = await c.env.DB.prepare(`SELECT * FROM Users where email =?`).bind( payload.email ).first();
  if ( user && c.req.param('id') ) {
    const pStmt = c.env.DB.prepare(`DELETE FROM profiles where user = ? and id = ?`).bind( user.id, c.req.param('id') );
    const mStmt = c.env.DB.prepare(`DELETE FROM mappings where profile = ?`).bind( c.req.param('id') );
    const result = await c.env.DB.batch([ pStmt, mStmt ]);
    console.log( `Delete: ${result}` );
    return c.json({message: "Deleted"});
  } else if ( user && !c.req.param('id') ) {
    c.status( 403 );
    return c.json({
      message: "Profile ID required"
    });
  } else {
    c.status( 401 );
    return c.json({message: "Not authorised"});
  }
});
api.post('/map', async c => {
  let mapping = await c.req.json();
  const payload = c.get('user');
  const profileStmt = c.env.DB.prepare(`SELECT p.id,p.user,p.name FROM Profiles p INNER JOIN Users u on p.user = u.id where u.email = ? and p.id = ?`).bind( payload.email, mapping.profile );
  const mappingStmt = c.env.DB.prepare(`SELECT * FROM Mappings where code = ?`).bind( mapping.code );
  const qResults = await c.env.DB.batch([ profileStmt, mappingStmt ]);
  if( qResults[0].results[0] && qResults[1].results[0] ) {
    // await c.env.DB.prepare('UPDATE mappings set profile = ? where code = ?').bind(mapping.profile, mapping.code).run();
    // mapping.id = qResults[1].results[0].id;
    // return c.json(mapping);
    c.status( 403 );
    return c.json({ message: "Card is already mapped to a profile." });
  } else if ( qResults[0].results[0] && !qResults[1].results[0] ) {
    let res = await c.env.DB.prepare('INSERT INTO mappings (profile, code) values(?, ?)').bind(mapping.profile, mapping.code).run();
    mapping.id = res.meta.last_row_id;
    return c.json(mapping);
  }
  c.status( 403 );
  return c.json({ message: "Unauthorised" });
});
api.get('/map', async c => {
  const payload = c.get('user');
  console.log( payload.email )
  const {results} = await c.env.DB.prepare(`SELECT m.id, p.id as profile,p.data, p.user, p.name, m.code,u.email FROM
  Mappings m INNER JOIN Profiles p on m.profile = p.id
  INNER JOIN Users u on p.user = u.id where u.email = ?`).bind( payload.email ).all();
  return c.json( results );
});
api.delete('/map/:id', async c => {
  const payload = c.get('user');
  let {results} = await c.env.DB.prepare(`SELECT m.id, p.id as profile,p.data, p.user, p.name, m.code,u.email FROM
  Mappings m INNER JOIN Profiles p on m.profile = p.id
  INNER JOIN Users u on p.user = u.id where u.email = ?`).bind( payload.email ).all();

  results = results.filter( f => f.id == c.req.param('id') && f.email == payload.email );
  if( results.length == 0 ) {
    c.status( 404 )
    return c.json({ message: "Not found to remove mapping" });
  }
  await c.env.DB.prepare(`DELETE FROM Mappings where ID = ?`).bind( c.req.param('id') ).run();
  return c.json({message: 'Done.'});
});

app.route("/auth", auth);
app.route("/api", api);

export default app;