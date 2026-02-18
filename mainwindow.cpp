#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pe_analyzer.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QTableWidgetItem>
#include <QColor>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {

    ui->setupUi(this);

    ui->tableSections->setColumnCount(10);
    ui->tableSections->setHorizontalHeaderLabels({
        "Name", "RVA", "Virtual Size", "Raw Size",
        "Entropy", "Threshold",
        "Flags", "EP Here", "RWX", "High Entropy"
    });

    ui->tableSections->horizontalHeader()->setStretchLastSection(true);
    ui->tableSections->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableSections->setSelectionBehavior(QAbstractItemView::SelectRows);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::on_actionOpen_triggered() {
    QString filePath = QFileDialog::getOpenFileName(
        this, "Open executable", "", "Executables (*.exe)"
        );

    if (filePath.isEmpty())
        return;

    PEAnalyzer analyzer;
    if (!analyzer.analyze(filePath.toStdString())) {
        QMessageBox::critical(this, "Error", "Failed to analyze file");
        return;
    }

    const auto& r = analyzer.result();

    ui->labelFileValue->setText(QString::fromStdString(r.filePath));
    ui->labelArchValue->setText(QString::fromStdString(r.arch));
    ui->labelSubsystemValue->setText(QString::fromStdString(r.subsystem));
    ui->labelImageBaseValue->setText(QString("0x%1").arg(r.imageBase, 0, 16));
    ui->labelEntryRvaValue->setText(QString("0x%1").arg(r.epRVA, 0, 16));
    ui->labelEntryVaValue->setText(QString("0x%1").arg(r.epVA, 0, 16));
    ui->labelSectionsValue->setText(QString::number(r.sectionCount));
    ui->labelScoreValue->setText(QString::number(r.suspicionScore));
    ui->labelVerdictValue->setText(QString::fromStdString(r.verdict));

    ui->tableSections->setRowCount(0);

    int row = 0;
    for (const auto& s : r.sections) {
        ui->tableSections->insertRow(row);

        ui->tableSections->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(s.name)));
        ui->tableSections->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(s.rva, 0, 16)));
        ui->tableSections->setItem(row, 2, new QTableWidgetItem(QString("0x%1").arg(s.virtualSize, 0, 16)));
        ui->tableSections->setItem(row, 3, new QTableWidgetItem(QString("0x%1").arg(s.rawSize, 0, 16)));
        ui->tableSections->setItem(row, 4, new QTableWidgetItem(QString::number(s.entropy, 'f', 2)));
        ui->tableSections->setItem(row, 5, new QTableWidgetItem(QString::number(s.threshold, 'f', 2)));

        QString flags;
        if (s.canRead) flags += "R ";
        if (s.canWrite) flags += "W ";
        if (s.canExecute) flags += "X ";
        if (s.containsCode) flags += "CODE ";
        ui->tableSections->setItem(row, 6, new QTableWidgetItem(flags.trimmed()));

        ui->tableSections->setItem(row, 7, new QTableWidgetItem(s.entryPointHere ? "YES" : "NO"));
        ui->tableSections->setItem(row, 8, new QTableWidgetItem(s.isRWX ? "YES" : "NO"));
        ui->tableSections->setItem(row, 9, new QTableWidgetItem(s.highEntropy ? "YES" : "NO"));

        if (s.entryPointHere) {
            for (int c = 0; c < ui->tableSections->columnCount(); c++)
                ui->tableSections->item(row, c)->setBackground(QColor(40, 80, 40));
        }

        if (s.highEntropy) {
            for (int c = 0; c < ui->tableSections->columnCount(); c++)
                ui->tableSections->item(row, c)->setBackground(QColor(80, 30, 30));
        }

        row++;
    }
}
