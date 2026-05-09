# Bash completion for idcert
# Installation:
#   System-wide:  sudo cp idcert_completion.bash /etc/bash_completion.d/idcert
#   Current user: cp idcert_completion.bash ~/.bash_completion.d/idcert
#                 echo 'source ~/.bash_completion.d/idcert' >> ~/.bashrc

_idcert_completion() {
    local cur prev words cword
    _init_completion || return

    local flags="--list --ca-chain"

    case "$prev" in
        idcert)
            # After 'idcert': show flags + files (.crt, .key, .pem, .cer)
            local files
            files=$(compgen -f -- "$cur" | while read -r f; do
                if [[ -d "$f" ]]; then
                    echo "$f/"
                elif [[ "$f" =~ \.(crt|key|pem|cer)$ ]]; then
                    echo "$f"
                fi
            done)
            COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
            while IFS= read -r f; do
                COMPREPLY+=("$f")
            done <<< "$files"
            return
            ;;
    esac

    # Track which flags have already been used
    local has_list=0 has_ca_chain=0
    for word in "${words[@]}"; do
        case "$word" in
            --list)     has_list=1 ;;
            --ca-chain) has_ca_chain=1 ;;
        esac
    done

    if [[ "$cur" == --* ]]; then
        # Show only flags that have not been used yet
        local available_flags=""
        [[ $has_list     -eq 0 ]] && available_flags+=" --list"
        [[ $has_ca_chain -eq 0 ]] && available_flags+=" --ca-chain"
        COMPREPLY=( $(compgen -W "$available_flags" -- "$cur") )
        return
    fi

    # Show .crt, .key, .pem, .cer files + directories
    COMPREPLY=()
    while IFS= read -r f; do
        [[ -n "$f" ]] && COMPREPLY+=("$f")
    done < <(compgen -f -- "$cur" | while read -r f; do
        if [[ -d "$f" ]]; then
            echo "$f/"
        elif [[ "$f" =~ \.(crt|key|pem|cer)$ ]]; then
            echo "$f"
        fi
    done)
}

complete -F _idcert_completion idcert
