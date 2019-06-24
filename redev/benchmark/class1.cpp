class base {
protected:
        int data;
public:
        virtual void foo() = 0;
};

class child: public base {
    

    public:
        virtual void foo()
        {   data = 2;  }
};

int main()
{
    base *o1 = new child();

    o1->foo();
    return 0;
}

