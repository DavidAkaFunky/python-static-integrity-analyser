a = source()
b = "AAAAA"
match a:
    case 1:
        w = 2
        sinkA()
    case None if b != "DDDDD":
        a = sanit(a)
        sinkB(a)
sinkC(w)