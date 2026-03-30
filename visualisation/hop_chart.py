import plotly.graph_objects as go
from typing import Optional


def build_hop_chart(hops: list) -> Optional[go.Figure]:
    """
    Builds a horizontal timeline chart showing the email hop path.
    Each hop is a node; the delay between hops is shown on the connector.
    Returns a Plotly Figure, or None if there are no hops.
    """
    if not hops:
        return None

    # ── Build node labels ─────────────────────────────────────────
    labels = []
    for hop in hops:
        from_s = hop.from_server or "Unknown"
        by_s = hop.by_server or "Unknown"
        time_s = str(hop.timestamp)[:19] if hop.timestamp else "No timestamp"
        labels.append(f"<b>Hop {hop.index}</b><br>{from_s}<br>→ {by_s}<br>{time_s}")

    x_positions = list(range(len(hops)))
    y_positions = [0] * len(hops)

    # ── Node colours — red if suspicious delay, else teal ─────────
    node_colours = []
    for hop in hops:
        if getattr(hop, "suspicious", False):
            node_colours.append("#E74C3C")
        elif hop.index == 1:
            node_colours.append("#2ECC71")   # green for origin
        else:
            node_colours.append("#2E86AB")   # teal for intermediate

    fig = go.Figure()

    # ── Draw connector lines between hops ─────────────────────────
    for i in range(len(hops) - 1):
        next_hop = hops[i + 1]
        delay_text = next_hop.delay_label if next_hop.delay_label else ""
        colour = "#E74C3C" if next_hop.suspicious else "#AAAAAA"

        # Line
        fig.add_trace(go.Scatter(
            x=[i, i + 1],
            y=[0, 0],
            mode="lines",
            line=dict(color=colour, width=3),
            hoverinfo="skip",
            showlegend=False,
        ))

        # Delay label on the line
        fig.add_annotation(
            x=(i + i + 1) / 2,
            y=0.08,
            text=f"<b>{delay_text}</b>",
            showarrow=False,
            font=dict(size=11, color=colour),
            bgcolor="white",
            borderpad=2,
        )

    # ── Draw nodes ────────────────────────────────────────────────
    fig.add_trace(go.Scatter(
        x=x_positions,
        y=y_positions,
        mode="markers+text",
        marker=dict(
            size=28,
            color=node_colours,
            line=dict(color="white", width=2),
        ),
        text=[str(h.index) for h in hops],
        textposition="middle center",
        textfont=dict(color="white", size=13, family="Arial Black"),
        hovertext=labels,
        hoverinfo="text",
        showlegend=False,
    ))

    # ── Server name labels below each node ────────────────────────
    for hop in hops:
        server = hop.by_server or hop.from_server or "Unknown"
        # Truncate long server names
        if len(server) > 25:
            server = server[:22] + "..."
        fig.add_annotation(
            x=hop.index - 1,
            y=-0.15,
            text=server,
            showarrow=False,
            font=dict(size=10, color="#555555"),
        )

    # ── Layout ────────────────────────────────────────────────────
    fig.update_layout(
        height=220,
        margin=dict(l=40, r=40, t=20, b=60),
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            range=[-0.5, len(hops) - 0.5],
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            range=[-0.4, 0.4],
        ),
        plot_bgcolor="white",
        paper_bgcolor="white",
        hovermode="closest",
    )

    return fig