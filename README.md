# 🛡️ PEGuard – Static PE Analysis Tool

**PEGuard** é uma ferramenta desenvolvida em **C++** voltada para análise estática de executáveis Windows (Portable Executable – PE). O projeto utiliza cálculo de entropia e heurísticas para identificar comportamentos suspeitos, técnicas de ofuscação e possíveis indicadores relacionados à análise de segurança.

---

## 🔎 Funcionalidades

O PEGuard realiza inspeções estruturais e heurísticas, incluindo:

* Identificação da arquitetura do binário (**x86 / x64**)
* Detecção do **Subsystem** (GUI ou Console)
* Análise de **ImageBase** e **Entry Point** (RVA e VA)
* Quantidade e características das seções
* Verificação de **flags de memória** (Read, Write, Execute)
* Detecção de seções **RWX**
* Cálculo de **entropia por seção** para identificar compressão ou criptografia
* Verificação de Entry Point localizado fora da `.text`
* Geração de **Suspicion Score** baseado em heurísticas

---

## 🧠 Objetivo do Projeto

O PEGuard foi criado com foco educacional e investigativo, explorando conceitos de baixo nível relacionados ao funcionamento interno de executáveis Windows, engenharia reversa e análise estática. A ferramenta busca auxiliar no entendimento de padrões comuns observados em binários potencialmente ofuscados ou suspeitos.

---

## ⚙️ Tecnologias Utilizadas

* C++
* Windows API
* Estrutura Portable Executable (PE)
* Conceitos de engenharia reversa e análise estática

---

## 🚀 Como usar

1. Compile o projeto em ambiente Windows.
2. Execute o binário passando um executável PE como entrada.
3. Analise o relatório gerado com as métricas e indicadores heurísticos.

## Interface
<img width="800" height="582" alt="image" src="https://github.com/user-attachments/assets/2c0383ee-bc75-47f4-94e1-56f9afed78c4" />

---

## 📌 Roadmap

* Análise de imports suspeitos
* Detecção básica de packers
* Heurísticas mais avançadas
* Expansão do sistema de scoring
* Extração e análise de strings
* Melhorias na interface

---

## ⚠️ Aviso

Este projeto possui finalidade **educacional e de pesquisa em segurança da informação**. Não deve ser utilizado para atividades maliciosas.
