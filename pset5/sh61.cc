#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <iostream>
#include <cstdio>
#include <map>

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__

// struct command
//    Data structure describing a command. Add your own stuff.
std::string name = "null";
std::string value = "null";

struct command {
    std::vector<std::string> args;
    pid_t pid = -1;      // process ID running this command, -1 if none
    command();
    ~command();
    command *next = nullptr;
    command *prev = nullptr;
    // variables for redirect (from section)
    std::string stdin_file;
    std::string stdout_file;
    std::string stderr_file;
    std::string stdappend_file;
    bool stdin_red = false;
    bool stdout_red = false;
    bool stderr_red = false;
    bool stdappend_red = false;
    int wstatus;
    int link = TYPE_SEQUENCE; // Last in list is always TYPE_SEQUENCE or TYPE_BACKGROUND
    void run();
};

// command::command()
//    This constructor function initializes a `command` structure. You may
//    add stuff to it as you grow the command structure.

command::command()
{
}

// command::~command()
//    This destructor function is called to delete a command.

command::~command()
{
    delete this->next; // fix leaks
}

// COMMAND EXECUTION

// command::run()
//    Creates a single child process running the command in `this`, and
//    sets `this->pid` to the pid of the child process.
//
//    If a child process cannot be created, this function should call
//    `_exit(EXIT_FAILURE)` (that is, `_exit(1)`) to exit the containing
//    shell or subshell. If this function returns to its caller,
//    `this->pid > 0` must always hold.
//
//    Note that this function must return to its caller *only* in the parent
//    process. The code that runs in the child process must `execvp` and/or
//    `_exit`.
//
//    PART 1: Fork a child process and run the command using `execvp`.
//       This will require creating a vector of `char*` arguments using
//       `this->args[N].c_str()`. Note that the last element of the vector
//       must be a `nullptr`.
//    PART 4: Set up a pipeline if appropriate. This may require creating a
//       new pipe (`pipe` system call), and/or replacing the child process's
//       standard input/output with parts of the pipe (`dup2` and `close`).
//       Draw pictures!
//    PART 7: Handle redirections.

void command::run()
{
    int pfd[2];
    // convert arguments
    char *converted_args[this->args.size() + 1];
    for (size_t i = 0; i < this->args.size(); i++)
    {
        if (args[i].c_str()[0] == '$')
        {
            if (this->args[i].substr(1, std::string::npos) == name)
            {
                converted_args[i] = (char *)(value.c_str());
            }
        }
        else
        {
            converted_args[i] = (char *)(this->args[i].c_str());
        }
    }
    converted_args[this->args.size()] = (nullptr);
    if ((this->args.size() == 3) && (this->args[1] == "="))
    {
        // printf("Name: %s\n", name.c_str());
        // printf("Value: %s\n", value.c_str());
        // printf("Variable assignment \n");
        name = converted_args[0];
        value = converted_args[2];   
    }
    if (this->link == TYPE_PIPE)
    {
        // std::cout << this->link << std::endl;
        // std::cout << (pipe(pfd)) << std::endl;
        assert(pipe(pfd) >= 0);
    }
    pid_t pa = fork();
    assert(pa >= 0);
    if (pa == 0) // check for child cd
    {
        if (this->args[0].compare("cd") == 0)
        {
            if (chdir(this->args[1].c_str()) < 0)
            {
                _exit(1);
            }
            else
            {
                _exit(0);
            }
        }
        if (this->link == TYPE_PIPE)
        {
            // merging, maintaining, and closing pipes
            dup2(pfd[1], 1);
            close(pfd[0]);
            close(pfd[1]);
        }
        assert(this->pid == -1);
        assert(this->args.size() > 0);
        // check for redirections
        if (this->stdin_red)
        {
            int fd = open(this->stdin_file.c_str(), O_RDONLY | O_CLOEXEC); // open standard w/ correct status or print error
            if (fd == -1)                                                  
            {
                fprintf(stderr, "No such file or directory\n"); 
                _exit(EXIT_FAILURE);
            }
            dup2(fd, 0); // clean up pipe ends
        }
        if (this->stdout_red)
        {
            int fd = open(this->stdout_file.c_str(), O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU); 
            if (fd == -1)                                                                    
            {
                fprintf(stderr, "No such file or directory\n"); 
                _exit(EXIT_FAILURE);
            }
            dup2(fd, 1); 
        }
        if (this->stderr_red)
        {
            int fd = open(this->stderr_file.c_str(), O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU); // opening standard error with permissions and recording the status
            if (fd == -1)                                                                    // if unable to open
            {
                fprintf(stderr, "No such file or directory\n"); 
                _exit(EXIT_FAILURE);
            }
            dup2(fd, 2); // fix pipe ends
        }
        if (this->stdappend_red)
        {
            int fd = open(this->stdappend_file.c_str(), O_CREAT | O_WRONLY | O_APPEND, S_IRWXU); // opening standard out with permissions and recording the status
            if (fd == -1)                                                                        // if unable to open
            {
                fprintf(stderr, "No such file or directory\n"); 
                _exit(EXIT_FAILURE);
            }
            dup2(fd, 1); // fix pipe ends
        }
        if (execvp(converted_args[0], converted_args) == 0)
        {
            _exit(0);
        }
    }
    else if (pa > 0) // check for parent cd 
    { 
        if (this->args[0].compare("cd") == 0)
        {
            assert(chdir(this->args[1].c_str()) <= 0);
        }

        if (this->link == TYPE_PIPE)
        {
            // merging, maintaining, and closing 
            dup2(pfd[0], 0);
            close(pfd[0]);
            close(pfd[1]);
        }
        this->pid = pa;
    }
}

void run_pipeline(command *c, command *c_last)
{
    // run arguments up pipe
    while (c->link == TYPE_PIPE)
    {
        c->run();
        c = c->next;
    }
    // Run last command before the pipe
    c->run();
    bool isAssign = (c->args.size() == 3) && (c->args[1] == "=");
    if ((c == c_last) && !(isAssign))
    {
        assert(waitpid(c->pid, &c->wstatus, 0) > 0);
    }
}

void run_conditional(command *c)
{
    // Check for cd commands
    command *firstc = c; 
    while (true)
    {
        if (c->args[0] == "cd")
        {
            assert(chdir(c->args[1].c_str()) <= 0); // change directory
        }
        if (c->link == TYPE_BACKGROUND || c->next == nullptr || c->link == TYPE_SEQUENCE)
        {
            break; 
        }
        c = c->next; // loop through arguments
    }
    c = firstc; // restore the command to the first

    // fork the conditional so we can run many processes together simultaneously we need to
    pid_t pa = fork();
    if (pa == 0) // child process
    {
        command *pipelinestart = c; // save the position of the beginning of the pipe
        while (c)
        {
            while (c->link == TYPE_PIPE) // run through the pipe
            {
                c = c->next;
            }
            run_pipeline(pipelinestart, c); // run the pipeline from the head

            if (c->link == TYPE_SEQUENCE || c->link == TYPE_BACKGROUND) // if it the next argument is running in the background, start running the next pipeline
            {
                break; // end of statement
            }
            else if (c->link == TYPE_AND) // check for &&
            {
                // check if command is false
                if (WIFEXITED(c->wstatus) == 0 || WEXITSTATUS(c->wstatus) != 0)
                {
                    while (c->link == TYPE_AND)
                    {
                        c = c->next; // if the status before "and" is false, we skip the next command
                    }
                }
            }
            else if (c->link == TYPE_OR) // check for ||
            {
                // check if command is true
                if (WIFEXITED(c->wstatus) && WEXITSTATUS(c->wstatus) == 0)
                {
                    while (c->link == TYPE_OR)
                    {
                        c = c->next; // if the status before "or" is true, we skip the next command
                    }
                }
            }
            c = c->next;       // move to the next conditional statement
            pipelinestart = c; // move the pipelinestart variable to the start of the next pipe
        }
        _exit(0); // exit child process
    }
    else // in the parent
    {
        c->pid = pa;
    }
}

// run_list(c)
//    Run the command *list* starting at `c`. Initially this just calls
//    `c->run()` and `waitpid`; you’ll extend it to handle command lists,
//    conditionals, and pipelines.
//
//    It is possible, and not too ugly, to handle lists, conditionals,
//    *and* pipelines entirely within `run_list`, but many students choose
//    to introduce `run_conditional` and `run_pipeline` functions that
//    are called by `run_list`. It’s up to you.
//
//    PART 1: Start the single command `c` with `c->run()`,
//        and wait for it to finish using `waitpid`.
//    The remaining parts may require that you change `struct command`
//    (e.g., to track whether a command is in the background)
//    and write code in `command::run` (or in helper functions).
//    PART 2: Introduce a loop to run a list of commands, waiting for each
//       to finish before going on to the next.
//    PART 3: Change the loop to handle conditional chains.
//    PART 4: Change the loop to handle pipelines. Start all processes in
//       the pipeline in parallel. The status of a pipeline is the status of
//       its LAST command.
//    PART 5: Change the loop to handle background conditional chains.
//       This may require adding another call to `fork()`!

void run_list(command *c)
{
    command *start = c;
    while (c)
    {
        while (c->link != TYPE_SEQUENCE && c->link != TYPE_BACKGROUND && c->next)
        { // keep parsing if there exists another argument and the current link is not a semicolon
            c = c->next;
        }
        run_conditional(start);
        // waitpid
        if (c->link != TYPE_BACKGROUND)
        {
            assert(waitpid(start->pid, &c->wstatus, 0) > 0); // waits for the process to complete before executing the next if it is not in the background
        }
        c = c->next; // jump to the next argument from semicolon
        start = c;
    }
    // std ::cout << WEXITSTATUS(wstatus) << std::endl;
    // fprintf(stderr, "command::run not done yet\n");
}

// parse_line(s)
//    Parse the command list in `s` and return it. Returns `nullptr` if
//    `s` is empty (only spaces). You’ll extend it to handle more token
//    types.

command *parse_line(const char *s)
{
    // section code
    shell_parser parser(s);
    command *chead = nullptr; // first command in list
    command *clast = nullptr; // last command in list
    command *ccur = nullptr;  // current command being built
    for (auto it = parser.begin(); it != parser.end(); ++it)
    {
        // printf("ID %s %d\n", it.str().c_str(), it.type());
        switch (it.type())
        {
        case TYPE_NORMAL:
            // Add a new argument to command
            if (!ccur)
            {
                ccur = new command;
                if (clast)
                {
                    clast->next = ccur;
                    ccur->prev = clast;
                }
                else
                {
                    chead = ccur;
                }
            }
            ccur->args.push_back(it.str());
            break;
        case TYPE_SEQUENCE:
        case TYPE_BACKGROUND:
        case TYPE_PIPE:
        case TYPE_AND:
        case TYPE_OR:
            // These operators terminate the current command.
            assert(ccur);
            clast = ccur;
            clast->link = it.type();
            ccur = nullptr;
            break;

        // Iterates through possible directions 
        case TYPE_REDIRECT_OP: 
            assert(ccur);
            if (it.str() == "<")
            {
                ccur->stdin_red = true;
                ++it;
                ccur->stdin_file = it.str();
            }
            else if (it.str() == ">")
            {
                ccur->stdout_red = true;
                ++it;
                ccur->stdout_file = it.str();
            }
            else if (it.str() == "2>")
            {
                ccur->stderr_red = true;
                ++it;
                ccur->stderr_file = it.str();
            }
            break;
        }
    }
    return chead;
}

int main(int argc, char *argv[])
{
    FILE *command_file = stdin;
    bool quiet = false;

    // Check for `-q` option
    if (argc > 1 && strcmp(argv[1], "-q") == 0)
    {
        quiet = true;
        --argc, ++argv;
    }

    // Read commands from file
    if (argc > 1)
    {
        command_file = fopen(argv[1], "rb");
        if (!command_file)
        {
            perror(argv[1]);
            return 1;
        }
    }

    // Moves shell to foreground and ignore SIGTTOU signal 
    set_signal_handler(SIGTTOU, SIG_IGN);

    char buf[BUFSIZ];
    int bufpos = 0;
    bool needprompt = true;

    while (!feof(command_file))
    {
        // Print the prompt at the beginning of the line
        if (needprompt && !quiet)
        {
            printf("sh61[%d]$ ", getpid());
            fflush(stdout);
            needprompt = false;
        }

        // Error check 
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == nullptr)
        {
            if (ferror(command_file) && errno == EINTR)
            {
                // ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            }
            else
            {
                if (ferror(command_file))
                {
                    perror("sh61");
                }
                break;
            }
        }

        // Run command line if it exists
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n'))
        {
            if (command *c = parse_line(buf))
            {
                run_list(c);
                delete c;
            }
            bufpos = 0;
            needprompt = 1;
        }

        // Handle zombie processes and interrupt requests
        while (true)
        {
            if (waitpid(-1, nullptr, WNOHANG) <= 0) // check exit processes
            {
                break; 
            }
        }
    }

    return 0;
}
