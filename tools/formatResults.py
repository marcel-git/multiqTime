import sys
import matplotlib.pyplot as plt


def createFigure(con_series, nocon_series, x_label, y_label, title, filename):
    # Generate x-axis values (indices)
    x = range(len(con_series))

    # Create the figure and axes
    fig, ax = plt.subplots()

    # Plot CON series
    ax.plot(x, con_series, label=x_label)

    # Plot NOCON series
    ax.plot(x, nocon_series, label=y_label)

    # Set the axis labels
    ax.set_xlabel('Run no.')
    ax.set_ylabel('Amount')

    # Set the title
    ax.set_title(title)

    # Add a legend
    ax.legend()
    plt.savefig(filename)
    # Display the plot
    plt.show()

if len(sys.argv) == 2:
    with open(sys.argv[1],"r") as file:
        contents = file.read()
        contents = '\n'.join(contents.split('\n')[1:-2])
        contents = '\n'.join([i[24:] for i in contents.split('\n')])
        contents = '\n'.join([i[:30] for i in contents.split('\n')])
        contents = contents.replace('i','').replace('|',';').replace(' ','')

        con_true_series = []
        con_false_series = []
        nocon_true_series = []
        nocon_false_series = []

        lines = contents.strip().split("\n")
        print(len(lines))
        for line in lines:
            parts = line.split(";")
            ic_value = None
            con_value = None
            nocon_value = None

            for part in parts:
                if part.startswith("IC:"):
                    ic_value = part.split(":")[1]
                elif part.startswith("CON:"):
                    con_value = int(part.split(":")[1])
                elif part.startswith("NOCON:"):
                    nocon_value = int(part.split(":")[1])

            if ic_value == "True":
                con_true_series.append(con_value)
                nocon_true_series.append(nocon_value)
            elif ic_value == "False":
                con_false_series.append(con_value)
                nocon_false_series.append(nocon_value)
        createFigure(con_true_series,nocon_true_series,"CON","NOCON","CON and NOCON series","./with_in_connection.png")
        createFigure(con_false_series,nocon_false_series,"NOCON","NOCON 1","Two NOCON series","./without_in_connection.png")
else:
    print("[!] Please provide a filepath")