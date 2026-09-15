import React, { useState, useMemo } from 'react';
import { 
  KeyRound, 
  Search, 
  Eye, 
  EyeOff, 
  Copy, 
  Check, 
  ExternalLink, 
  Filter, 
  Terminal, 
  Globe, 
  FileCode, 
  ShieldAlert, 
  LockOpen,
  ArrowRight,
  Database
} from 'lucide-react';
import { CleartextItem, CleartextCategory } from '../types';

interface UnencryptedDataViewProps {
  items: CleartextItem[];
  onSelectPacket: (packetId: number) => void;
}

const CATEGORIES: CleartextCategory[] = [
  'Credentials & Passwords',
  'Session & Auth Tokens',
  'Web Forms & Requests',
  'Terminal & Shell Sessions',
  'File & Protocol Commands',
  'DNS Activity',
  'Extracted PII & Keys',
];

export const UnencryptedDataView: React.FC<UnencryptedDataViewProps> = ({
  items,
  onSelectPacket,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Toggle reveal for a specific secret
  const toggleReveal = (id: string) => {
    setRevealedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Copy to clipboard
  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Counts by category
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: items.length };
    for (const cat of CATEGORIES) {
      counts[cat] = 0;
    }
    for (const item of items) {
      counts[item.category] = (counts[item.category] || 0) + 1;
    }
    return counts;
  }, [items]);

  // Protocols present
  const availableProtocols = useMemo(() => {
    const protos = new Set<string>();
    items.forEach(i => protos.add(i.protocol));
    return Array.from(protos);
  }, [items]);

  // Filtered items
  const filteredItems = useMemo(() => {
    return items.filter(item => {
      if (selectedCategory !== 'all' && item.category !== selectedCategory) return false;
      if (riskFilter !== 'all' && item.riskLevel !== riskFilter) return false;
      if (protocolFilter !== 'all' && item.protocol !== protocolFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesLabel = item.label.toLowerCase().includes(q);
        const matchesVal = item.value.toLowerCase().includes(q);
        const matchesSecVal = item.secondaryValue?.toLowerCase().includes(q) || false;
        const matchesIp = item.sourceIp.includes(q) || item.destIp.includes(q);
        const matchesContext = item.contextSnippet.toLowerCase().includes(q);
        if (!matchesLabel && !matchesVal && !matchesSecVal && !matchesIp && !matchesContext) {
          return false;
        }
      }
      return true;
    });
  }, [items, selectedCategory, riskFilter, protocolFilter, searchQuery]);

  const getCategoryIcon = (category: CleartextCategory) => {
    switch (category) {
      case 'Credentials & Passwords': return <KeyRound className="w-4 h-4 text-rose-400" />;
      case 'Session & Auth Tokens': return <LockOpen className="w-4 h-4 text-amber-400" />;
      case 'Web Forms & Requests': return <Globe className="w-4 h-4 text-blue-400" />;
      case 'Terminal & Shell Sessions': return <Terminal className="w-4 h-4 text-emerald-400" />;
      case 'File & Protocol Commands': return <FileCode className="w-4 h-4 text-indigo-400" />;
      case 'DNS Activity': return <Database className="w-4 h-4 text-cyan-400" />;
      case 'Extracted PII & Keys': return <ShieldAlert className="w-4 h-4 text-purple-400" />;
      default: return <FileCode className="w-4 h-4 text-slate-400" />;
    }
  };

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
            Critical Risk
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/30">
            High Risk
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">
            Medium
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider bg-slate-800 text-slate-400 border border-slate-700">
            Low / Info
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      
      {/* Category Pills Bar */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-thin">
        <button
          onClick={() => setSelectedCategory('all')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all flex items-center gap-1.5 ${
            selectedCategory === 'all'
              ? 'bg-amber-500 text-slate-950 font-bold shadow-md shadow-amber-500/20'
              : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
          }`}
        >
          <span>All Findings</span>
          <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${selectedCategory === 'all' ? 'bg-slate-950/20 text-slate-950' : 'bg-slate-800 text-slate-400'}`}>
            {categoryCounts.all || 0}
          </span>
        </button>

        {CATEGORIES.map(cat => {
          const count = categoryCounts[cat] || 0;
          const isSelected = selectedCategory === cat;
          return (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all flex items-center gap-1.5 ${
                isSelected
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800'
              }`}
            >
              {getCategoryIcon(cat)}
              <span>{cat}</span>
              <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${isSelected ? 'bg-amber-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-400'}`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search cleartext credentials, hosts, tokens..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 transition-colors"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          {/* Protocol Filter */}
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={protocolFilter}
              onChange={e => setProtocolFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-amber-500"
            >
              <option value="all">All Protocols</option>
              {availableProtocols.map(p => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>

          {/* Risk Filter */}
          <select
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-amber-500"
          >
            <option value="all">All Risk Levels</option>
            <option value="critical">Critical Risk Only</option>
            <option value="high">High Risk</option>
            <option value="medium">Medium Risk</option>
            <option value="low">Low Risk</option>
          </select>
        </div>
      </div>

      {/* Results Header */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1">
        <span>
          Showing <strong className="text-white font-mono">{filteredItems.length}</strong> of{' '}
          <span className="font-mono">{items.length}</span> unencrypted items
        </span>
        {items.length > 0 && (
          <span className="text-amber-400/90 flex items-center gap-1">
            <LockOpen className="w-3.5 h-3.5" />
            Plaintext data collected automatically from packet streams
          </span>
        )}
      </div>

      {/* Items List */}
      {filteredItems.length === 0 ? (
        <div className="bg-slate-900/40 border border-dashed border-slate-800 rounded-xl p-12 text-center">
          <KeyRound className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h4 className="text-sm font-semibold text-slate-300">No unencrypted items match your filter</h4>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            Try adjusting your search criteria, switching categories, or loading another PCAP sample.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {filteredItems.map(item => {
            const isRevealed = revealedIds.has(item.id);
            const isPasswordType = item.type === 'password' || item.type === 'basic_auth' || item.type === 'ftp_cred';
            const displayValue = isPasswordType && !isRevealed ? '••••••••••••••••' : item.value;

            return (
              <div 
                key={item.id}
                className="bg-slate-900/70 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all shadow-sm flex flex-col gap-3 group"
              >
                {/* Top Row: Category, Label, Badges, Packet Link */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-slate-800 border border-slate-700/80">
                      {getCategoryIcon(item.category)}
                    </div>
                    <div>
                      <h4 className="text-xs font-semibold text-white tracking-tight flex items-center gap-2">
                        <span>{item.label}</span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {item.protocol}
                        </span>
                      </h4>
                      <p className="text-[11px] text-slate-400 font-mono flex items-center gap-1 mt-0.5">
                        <span>{item.sourceIp}{item.sourcePort ? `:${item.sourcePort}` : ''}</span>
                        <ArrowRight className="w-3 h-3 text-slate-600 inline" />
                        <span>{item.destIp}{item.destPort ? `:${item.destPort}` : ''}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {getRiskBadge(item.riskLevel)}

                    <button
                      onClick={() => onSelectPacket(item.packetId)}
                      title="Inspect packet in hex viewer"
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-mono border border-slate-700 transition-colors flex items-center gap-1"
                    >
                      <span>Packet #{item.packetId}</span>
                      <ExternalLink className="w-3 h-3 text-cyan-400" />
                    </button>
                  </div>
                </div>

                {/* Secret Value Block */}
                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-2.5 flex items-center justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    {item.secondaryValue && (
                      <div className="text-[11px] font-mono text-cyan-400 mb-0.5 truncate">
                        {item.secondaryValue}
                      </div>
                    )}
                    <div className="text-xs font-mono text-white tracking-wide break-all select-all font-semibold">
                      {displayValue}
                    </div>
                  </div>

                  <div className="flex items-center gap-1 shrink-0">
                    {isPasswordType && (
                      <button
                        onClick={() => toggleReveal(item.id)}
                        title={isRevealed ? "Mask password" : "Reveal password"}
                        className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition-colors"
                      >
                        {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    )}

                    <button
                      onClick={() => handleCopy(item.id, item.value)}
                      title="Copy value"
                      className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white rounded transition-colors"
                    >
                      {copiedId === item.id ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Context Snippet */}
                {item.contextSnippet && (
                  <div className="text-[11px] text-slate-400 font-mono bg-slate-950/40 rounded px-2.5 py-1.5 border border-slate-800/40 line-clamp-2">
                    <span className="text-slate-500 uppercase text-[9px] mr-1">Context:</span>
                    {item.contextSnippet}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

    </div>
  );
};
