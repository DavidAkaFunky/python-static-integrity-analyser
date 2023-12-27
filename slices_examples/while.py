uname = "user"
a = cursor.execute("SELECT pass FROM users WHERE user='%s'" % uname)
a = a+1
while a:
    # just make random vars and names like: xd, c and whatever you want
    if xd == 78:
        a = cursor.fetchone()
    elif xd + c == 45:
        a = cursor.fetchone()
    
    if si == 1:
        a = cursor.fetchone()
        xd = ChatMessageForm()

    if c == 1:
        si = ChatMessageForm()
    c = a[0]
else:
    c = 123

cursor.execute("SELECT pass FROM users WHERE user='%s'" % c)

